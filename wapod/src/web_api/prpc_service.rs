use std::ops::Deref;

use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use rocket::{
    data::{ByteUnit, Limits, ToByteUnit as _},
    http::{ContentType, Status},
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
use tracing::{error, field::Empty, info};
use wapo_host::ShortId;
use wapod_crypto::query_signature::{Query, Signer};
use wapod_rpc as rpc;

use crate::worker_key::worker_identity_key;

use super::{read_data, Worker};

pub struct Call {
    worker: Worker,
}

impl Deref for Call {
    type Target = Worker;

    fn deref(&self) -> &Self::Target {
        &self.worker
    }
}

impl Call {
    pub fn new(worker: Worker) -> Self {
        Self { worker }
    }
}

impl OperationRpc for Call {
    async fn worker_init(self, request: pb::InitArgs) -> Result<pb::InitResponse> {
        if request.salt.len() > 64 {
            bail!("the salt is too long");
        }
        let session_seed = self.init(&request.salt)?;
        let session = self.session().context("no worker session")?;
        Ok(pb::InitResponse {
            session: session.to_vec(),
            session_seed: session_seed.to_vec(),
        })
    }

    async fn worker_exit(self) -> Result<()> {
        std::process::exit(0);
    }

    async fn blob_put(self, request: pb::Blob) -> Result<pb::Blob> {
        let loader = self.blob_loader();
        let hash = loader
            .put(
                &request.hash,
                &mut &request.body[..],
                &request.hash_algorithm,
            )
            .await
            .context("failed to put object")?;
        Ok(pb::Blob {
            hash,
            hash_algorithm: request.hash_algorithm,
            body: vec![],
        })
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
            .deploy_app(manifest)
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
            session: self.session().context("no worker session")?,
            nonce: rand::thread_rng().gen(),
            apps: vec![],
        };
        self.for_each_app(addresses, |address, app| {
            let m = app.metrics();
            metrics.apps.push(rpc::types::AppMetrics {
                address,
                session: app.session,
                running_time_ms: m.duration.as_millis() as u64,
                gas_consumed: m.gas_comsumed,
                network_ingress: m.net_ingress,
                network_egress: m.net_egress,
                storage_read: m.storage_read,
                storage_write: m.storage_written,
                starts: m.starts,
            });
        });
        let encoded_metrics = metrics.encode();
        let signature =
            worker_identity_key().sign(wapod_crypto::ContentType::Metrics, encoded_metrics);
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
        } else {
            let signature = request.decode_signature()?;
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
        let decrypted = worker_identity_key()
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
        let pubkey = worker_identity_key().public().to_array();
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
            wapod_crypto::ContentType::WorkerAttestation,
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
            pubkey: worker_identity_key().public().to_array(),
            versioned_endpoints: VersionedWorkerEndpoints::V1(request.endpoints),
            signing_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("failed to get time")?
                .as_millis() as u64,
        };
        let signature = worker_identity_key().sign(
            wapod_crypto::ContentType::EndpointInfo,
            endpoint_payload.encode(),
        );
        Ok(pb::SignEndpointsResponse::new(endpoint_payload, signature))
    }
}

fn compat_app_version() -> u32 {
    let (major, minor, patch) = (3_u32, 0_u32, 0_u32);
    (major << 16) + (minor << 8) + patch
}

impl UserRpc for Call {
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

pub async fn handle_prpc<S>(
    worker: &State<Worker>,
    method: &str,
    data: Option<Data<'_>>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Vec<u8>, Custom<Vec<u8>>>
where
    S: From<Call> + PrpcService,
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
