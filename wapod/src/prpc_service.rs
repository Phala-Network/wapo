use std::{
    ops::Deref,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use rocket::{
    data::{ByteUnit, Limits, ToByteUnit as _},
    http::{ContentType, Status},
    request::FromParam,
    response::status::Custom,
    Data, State,
};
use rpc::prpc::{operation_server::OperationRpc, user_server::UserRpc};
use rpc::{
    prpc::{
        self as pb,
        server::{Error as RpcError, Service as PrpcService},
        WorkerInfo,
    },
    types::{VersionedWorkerEndpoints, WorkerEndpointPayload},
};
use scale::Encode;
use sp_core::crypto::{AccountId32, Ss58Codec};
use tracing::{error, field::Empty, info, warn};
use wapo_host::{
    rocket_stream::{RequestInfo, StreamResponse},
    MetricsToken, ShortId,
};
use wapod_crypto::query_signature::{Query, Signer};
use wapod_rpc::{
    self as rpc,
    prpc::{operation_server::OperationServer, server::ComposedService, user_server::UserServer},
};

use crate::{
    config::{KeyProvider, WorkerConfig},
    Worker,
};

pub type UserService<T> = ComposedService<Call<T>, (UserServer<Call<T>>,)>;
pub type AdminService<T> = ComposedService<Call<T>, (OperationServer<Call<T>>,)>;

#[derive(Debug)]
pub struct HexBytes(pub Vec<u8>);
impl<'r> FromParam<'r> for HexBytes {
    type Error = &'static str;

    fn from_param(param: &str) -> Result<Self, Self::Error> {
        let param = param.trim_start_matches("0x");
        let bytes = hex::decode(param).map_err(|_| "Invalid hex string")?;
        Ok(HexBytes(bytes))
    }
}

pub enum ReadDataError {
    IoError,
    PayloadTooLarge,
}

impl From<ReadDataError> for Custom<&'static str> {
    fn from(value: ReadDataError) -> Self {
        match value {
            ReadDataError::IoError => Custom(Status::ServiceUnavailable, "Read body failed"),
            ReadDataError::PayloadTooLarge => Custom(Status::PayloadTooLarge, "Entity too large"),
        }
    }
}

impl From<ReadDataError> for Custom<Vec<u8>> {
    fn from(value: ReadDataError) -> Self {
        let custom = Custom::<&'static str>::from(value);
        Custom(custom.0, custom.1.as_bytes().to_vec())
    }
}

async fn read_data(data: Data<'_>, limit: ByteUnit) -> Result<Vec<u8>, ReadDataError> {
    let stream = data.open(limit);
    let data = stream.into_bytes().await.or(Err(ReadDataError::IoError))?;
    if !data.is_complete() {
        return Err(ReadDataError::PayloadTooLarge);
    }
    Ok(data.into_inner())
}

pub struct Call<T> {
    worker: Worker<T>,
}

impl<T> Deref for Call<T> {
    type Target = Worker<T>;

    fn deref(&self) -> &Self::Target {
        &self.worker
    }
}

impl<T: WorkerConfig> Call<T> {
    pub fn new(worker: Worker<T>) -> Self {
        Self { worker }
    }
}

impl<T: WorkerConfig> OperationRpc for Call<T> {
    async fn worker_init(self, request: pb::InitArgs) -> Result<pb::InitResponse> {
        if request.pnonce.len() > 64 {
            bail!("the salt is too long");
        }
        let account = AccountId32::from_string(&request.recipient).context("invalid account")?;
        let update = self.init(&request.pnonce, account.into())?;
        let signature = T::KeyProvider::get_key()
            .sign(wapod_types::ContentType::SessionUpdate, update.encode());
        let pubkey = T::KeyProvider::get_key().public();
        Ok(pb::InitResponse::new(
            update,
            signature,
            pubkey.as_bytes().to_vec(),
        ))
    }

    async fn worker_exit(self) -> Result<()> {
        std::process::exit(0);
    }

    async fn blob_put(self, request: pb::Blob) -> Result<pb::Blob> {
        let loader = self.blob_loader();
        let hash = loader
            .put(&request.hash, &mut &request.body[..])
            .await
            .context("failed to put object")?;
        Ok(pb::Blob { hash, body: vec![] })
    }

    async fn blob_exists(self, request: pb::Blob) -> Result<pb::Boolean> {
        let loader = self.blob_loader();
        Ok(pb::Boolean {
            value: loader.exists(&request.hash),
        })
    }

    async fn blob_remove(self, request: pb::Blob) -> Result<()> {
        let loader = self.blob_loader();
        loader
            .remove(&request.hash)
            .context("failed to remove object")
    }

    #[tracing::instrument(name="app.deploy", skip_all, fields(addr=Empty))]
    async fn app_deploy(self, request: pb::DeployArgs) -> Result<pb::DeployResponse> {
        if self.session().is_none() {
            bail!("no worker session");
        }
        let manifest = request.manifest.ok_or(anyhow::Error::msg("No manifest"))?;
        let info = self
            .deploy_app(manifest.into(), true, request.reuse_instances)
            .await
            .context("failed to deploy app")?;
        info!("app deployed, address={}", hex_fmt::HexFmt(&info.address));
        Ok(pb::DeployResponse {
            address: info.address.to_vec(),
            session: info.session.to_vec(),
        })
    }

    #[tracing::instrument(name="app.remove", fields(id = %ShortId(&request.address)), skip_all)]
    async fn app_remove(self, request: pb::Address) -> Result<()> {
        self.remove_app(request.decode_address()?).await?;
        Ok(())
    }

    #[tracing::instrument(name="app.start", fields(id = %ShortId(&request.address)), skip_all)]
    async fn app_start(self, request: pb::Address) -> Result<()> {
        self.start_app(request.decode_address()?, false).await?;
        Ok(())
    }

    #[tracing::instrument(name="app.stop", fields(id = %ShortId(&request.address)), skip_all)]
    async fn app_stop(self, request: pb::Address) -> Result<()> {
        self.stop_app(request.decode_address()?).await?;
        Ok(())
    }

    async fn app_metrics(self, request: pb::Addresses) -> Result<pb::AppMetricsResponse> {
        let addresses = request.decode_addresses()?;
        let addresses = if addresses.is_empty() {
            None
        } else {
            Some(&addresses[..])
        };
        let mut metrics = rpc::types::AppsMetrics {
            token: MetricsToken {
                sn: self.worker.bump_metrics_sn(),
                session: self.session().context("no worker session")?,
                nonce: rand::thread_rng().gen(),
            },
            apps: Default::default(),
        };

        self.for_each_app(addresses, |address, app| {
            let m = app.metrics();
            let todo = "meter the storage and memory usage";
            metrics.apps.0.push(rpc::types::AppMetrics {
                address,
                session: app.session,
                running_time_ms: m.duration.as_millis() as u64,
                gas_consumed: m.gas_consumed,
                network_ingress: m.net_ingress,
                network_egress: m.net_egress,
                storage_read: m.storage_read,
                storage_write: m.storage_written,
                tip: m.tip,
                starts: m.starts,
                storage_used: 0,
                memory_used: 0,
            });
        });
        let metrics = rpc::types::VersionedAppsMetrics::V0(metrics);
        let encoded_metrics = metrics.encode();
        let signature =
            T::KeyProvider::get_key().sign(wapod_types::ContentType::Metrics, encoded_metrics);
        Ok(pb::AppMetricsResponse::new(metrics, signature))
    }

    #[tracing::instrument(name="app.resize", fields(id = %ShortId(&request.address)), skip_all)]
    async fn app_resize(self, request: pb::ResizeArgs) -> Result<pb::Number> {
        info!(new_size = request.instances, "resizing app");
        let address = request.decode_address()?;
        self.resize_app_instances(address, request.instances as usize, false)
            .await?;
        let number = self.num_instances_of(address).ok_or(RpcError::NotFound)?;
        Ok(pb::Number {
            value: number as u64,
        })
    }

    async fn app_list(self, request: pb::AppListArgs) -> Result<pb::AppListResponse> {
        let count = if request.count > 0 {
            request.count as _
        } else {
            usize::MAX
        };
        let apps = self
            .list(request.start as _, count)
            .into_iter()
            .map(|info| {
                pb::AppInfo::new(
                    info.sn,
                    info.address,
                    info.running_instances as _,
                    info.last_query_elapsed_secs,
                    info.reuse_instances,
                    Some(info.manifest),
                )
            })
            .collect();
        Ok(pb::AppListResponse { apps })
    }

    async fn app_remove_all(self) -> Result<()> {
        self.clear();
        Ok(())
    }

    async fn info(self) -> Result<WorkerInfo> {
        Ok(self.worker.info(true))
    }

    async fn app_query(self, request: pb::QueryArgs) -> Result<pb::QueryResponse> {
        let caller = if request.encoded_signature.is_empty() {
            None
        } else if let Some(signature) = request.decode_signature()? {
            let query = Query {
                address: request.address.clone(),
                path: request.path.clone(),
                payload: request.payload.clone(),
            };
            let caller = signature
                .signer
                .verify_query(query, &signature.signature, signature.signature_type)
                .map_err(|err| anyhow!("failed to verify the signature: {err:?}"))?;
            Some(caller)
        } else {
            None
        };
        let output = self
            .worker
            .query(
                caller,
                request.decode_address()?,
                request.path,
                request.payload,
            )
            .await?;
        Ok(pb::QueryResponse { output })
    }

    async fn app_encrypted_query(
        self,
        mut request: pb::EncryptedQueryArgs,
    ) -> Result<pb::QueryResponse> {
        let decrypted = T::KeyProvider::get_key()
            .decrypt_message(&request.pubkey, &mut request.encrypted_payload)
            .context("failed to decrypt the payload")?;
        let args: pb::QueryArgs = pb::Message::decode(&mut decrypted.as_slice())
            .context("failed to decode the query args")?;
        Self::app_query(self, args).await
    }

    async fn sign_register_info(
        self,
        request: pb::SignRegisterInfoArgs,
    ) -> Result<pb::SignRegisterInfoResponse> {
        let pubkey = T::KeyProvider::get_key().public().to_array();
        let runtime_info = rpc::types::WorkerRegistrationInfoV2 {
            version: compat_app_version(),
            machine_id: vec![],
            pubkey,
            ecdh_pubkey: pubkey,
            genesis_block_hash: request.decode_genesis_block_hash()?,
            features: vec![],
            operator: request.decode_operator()?,
            para_id: request.para_id,
            max_consensus_version: 0,
        };
        let report = crate::sgx::quote(
            wapod_types::ContentType::WorkerAttestation,
            &runtime_info.encode(),
        )
        .map(|quote| rpc::types::AttestationReport::SgxDcap {
            quote,
            collateral: None,
        });
        Ok(pb::SignRegisterInfoResponse::new(runtime_info, report))
    }

    async fn sign_endpoints(
        self,
        request: pb::SignEndpointsArgs,
    ) -> Result<pb::SignEndpointsResponse> {
        let endpoint_payload = WorkerEndpointPayload {
            pubkey: T::KeyProvider::get_key().public().to_array(),
            versioned_endpoints: VersionedWorkerEndpoints::V1(request.endpoints),
            signing_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("failed to get time")?
                .as_millis() as u64,
        };
        let signature = T::KeyProvider::get_key().sign(
            wapod_types::ContentType::EndpointInfo,
            endpoint_payload.encode(),
        );
        Ok(pb::SignEndpointsResponse::new(endpoint_payload, signature))
    }

    async fn sign_worker_description(
        self,
        request: pb::SignWorkerDescriptionArgs,
    ) -> Result<pb::SignWorkerDescriptionResponse> {
        let pair = T::KeyProvider::get_key();
        let worker_description = rpc::types::WorkerDescription {
            prices: request.decode_prices()?,
            description: request.description.into(),
        };
        let signature = pair.sign(
            wapod_types::ContentType::WorkerDescription,
            worker_description.encode(),
        );
        let signed = rpc::types::SignedWorkerDescription {
            worker_description,
            signature: signature.into(),
            worker_pubkey: pair.public().to_array(),
        };
        Ok(pb::SignWorkerDescriptionResponse::new(signed))
    }

    async fn set_bench_app(self, request: pb::SetBenchAppArgs) -> Result<()> {
        let address = request.decode_app_address().ok().flatten();
        self.worker.set_bench_app(address, request.instances);
        if let Some(address) = address {
            self.worker
                .resize_app_instances(address, request.instances as _, false)
                .await?;
        }
        Ok(())
    }
}

fn compat_app_version() -> u32 {
    let (major, minor, patch) = (3_u32, 0_u32, 0_u32);
    (major << 16) + (minor << 8) + patch
}

impl<T: WorkerConfig> UserRpc for Call<T> {
    async fn info(self) -> Result<WorkerInfo> {
        Ok(self.worker.info(false))
    }

    async fn query(self, request: pb::QueryArgs) -> Result<pb::QueryResponse> {
        OperationRpc::app_query(self, request).await
    }

    async fn encrypted_query(self, request: pb::EncryptedQueryArgs) -> Result<pb::QueryResponse> {
        OperationRpc::app_encrypted_query(self, request).await
    }
}

pub async fn handle_prpc<S, T>(
    worker: &State<Worker<T>>,
    method: &str,
    data: Option<Data<'_>>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Vec<u8>, Custom<Vec<u8>>>
where
    S: From<Call<T>> + PrpcService,
    T: WorkerConfig,
{
    let data = match data {
        Some(data) => {
            let limit = limit_for_method(method, limits);
            read_data(data, limit).await?
        }
        None => vec![],
    };
    let json = json || content_type.map(|t| t.is_json()).unwrap_or(false);
    let worker = (*worker).clone();
    let call = Call::new(worker);
    let data = data.to_vec();
    let result = dispatch_prpc(method.into(), data, json, S::from(call)).await;
    let (status_code, output) = result;
    if status_code == 200 {
        Ok(output)
    } else {
        let custom = if let Some(status) = Status::from_code(status_code) {
            Custom(status, output)
        } else {
            error!(status_code, "prpc: invalid status code!");
            Custom(Status::ServiceUnavailable, vec![])
        };
        Err(custom)
    }
}

fn limit_for_method(method: &str, limits: &Limits) -> ByteUnit {
    if let Some(v) = limits.get(method) {
        return v;
    }
    10.mebibytes()
}

async fn dispatch_prpc(
    path: String,
    data: Vec<u8>,
    json: bool,
    server: impl PrpcService,
) -> (u16, Vec<u8>) {
    use rpc::prpc::server::{Error, ProtoError};

    info!("dispatching request: {}", path);
    let result = server.dispatch_request(&path, data, json).await;
    let (code, data) = match result {
        Ok(data) => (200, data),
        Err(err) => {
            error!("rpc error: {:?}", err);
            let (code, error) = match err {
                Error::NotFound => (404, "method Not Found".to_string()),
                Error::DecodeError(err) => (400, format!("DecodeError({err:?})")),
                Error::BadRequest(msg) => (400, msg),
            };
            if json {
                let body = serde_json::to_string_pretty(&serde_json::json!({ "error": error }))
                    .unwrap_or_else(|_| r#"{"error": "failed to encode the error"}"#.to_string())
                    .into_bytes();
                (code, body)
            } else {
                (
                    code,
                    pb::codec::encode_message_to_vec(&ProtoError::new(error)),
                )
            }
        }
    };
    (code, data)
}

pub async fn connect_vm<'r, T: WorkerConfig>(
    state: &State<Worker<T>>,
    head: RequestInfo,
    id: HexBytes,
    path: PathBuf,
    body: Option<Data<'r>>,
) -> Result<StreamResponse, (Status, String)> {
    let address =
        id.0.try_into()
            .map_err(|_| (Status::BadRequest, "invalid address".to_string()))?;
    let guard = state
        .prepare_instance_for_query(address, 0)
        .await
        .map_err(|err| {
            warn!("failed to prepare query: {err:?}");
            (Status::NotFound, err.to_string())
        })?;
    let command_tx = state
        .sender_for(address, 0)
        .ok_or((Status::NotFound, Default::default()))?;
    let path = path
        .to_str()
        .ok_or((Status::BadRequest, "invalid path".to_string()))?;
    let result = wapo_host::rocket_stream::connect(head, path, body, command_tx, guard).await;
    match result {
        Ok(response) => Ok(response),
        Err(err) => Err((Status::InternalServerError, err.to_string())),
    }
}
