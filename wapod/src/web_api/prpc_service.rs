use std::ops::Deref;

use anyhow::Context;
use rand::Rng;
use rocket::{
    data::{ByteUnit, Limits, ToByteUnit as _},
    http::{ContentType, Status},
    response::status::Custom,
    Data, State,
};
use rpc::prpc::{
    self as pb,
    server::{Error as RpcError, Service as PrpcService},
    WorkerInfo,
};
use rpc::prpc::{operation_server::OperationRpc, user_server::UserRpc};
use scale::Encode;
use tracing::{error, field::Empty, info, warn};
use wapo_host::ShortId;
use wapod_rpc as rpc;

type Result<T, E = RpcError> = std::result::Result<T, E>;

use crate::worker_key::load_or_generate_key;

use super::{read_data, Worker};

pub struct Call {
    worker: Worker,
    caller: Option<()>,
}

impl Deref for Call {
    type Target = Worker;

    fn deref(&self) -> &Self::Target {
        &self.worker
    }
}

impl Call {
    pub fn new(worker: Worker) -> Self {
        Self {
            worker,
            caller: None,
        }
    }
}

impl OperationRpc for Call {
    async fn worker_init(&self, request: pb::InitArgs) -> Result<pb::InitResponse> {
        if request.salt.len() > 64 {
            return Err(RpcError::BadRequest("Salt too long".into()));
        }
        let session_seed = self.init(&request.salt)?;
        let session = self.session().context("No worker session")?;
        Ok(pb::InitResponse {
            session: session.to_vec(),
            session_seed: session_seed.to_vec(),
        })
    }

    async fn worker_exit(&self) -> Result<()> {
        std::process::exit(0);
    }

    async fn blob_put(&self, request: pb::Blob) -> Result<pb::Blob> {
        let loader = self.blob_loader();
        let hash = loader
            .put(
                &request.hash,
                &mut &request.body[..],
                &request.hash_algorithm,
            )
            .await
            .map_err(|err| {
                warn!("Failed to put object: {err}");
                RpcError::BadRequest(format!("Failed to put object: {err}"))
            })?;
        Ok(pb::Blob {
            hash,
            hash_algorithm: request.hash_algorithm,
            body: vec![],
        })
    }

    async fn blob_exists(&self, request: pb::Blob) -> Result<pb::Boolean> {
        let loader = self.blob_loader();
        Ok(pb::Boolean {
            value: loader.exists(&request.hash),
        })
    }

    async fn blob_remove(&self, request: pb::Blob) -> Result<()> {
        let loader = self.blob_loader();
        loader
            .remove(&request.hash)
            .map_err(|err| RpcError::BadRequest(format!("Failed to remove object: {err}")))
    }

    #[tracing::instrument(name="app.deploy", skip_all, fields(addr=Empty))]
    async fn app_deploy(&self, request: pb::DeployArgs) -> Result<pb::DeployResponse> {
        if self.session().is_none() {
            return Err(RpcError::BadRequest("No worker session".into()));
        }
        let manifest = request
            .manifest
            .ok_or(RpcError::BadRequest("No manifest".into()))?;
        let info = self
            .deploy_app(manifest)
            .await
            .context("Failed to deploy app")?;
        info!("App deployed, address={}", hex_fmt::HexFmt(&info.address));
        Ok(pb::DeployResponse {
            address: info.address.to_vec(),
            session: info.session.to_vec(),
        })
    }

    #[tracing::instrument(name="app.remove", fields(id = %ShortId(&request.address)), skip_all)]
    async fn app_remove(&self, request: pb::Address) -> Result<()> {
        self.remove_app(request.decode_address()?).await?;
        Ok(())
    }

    #[tracing::instrument(name="app.start", fields(id = %ShortId(&request.address)), skip_all)]
    async fn app_start(&self, request: pb::Address) -> Result<()> {
        self.start_app(request.decode_address()?, false).await?;
        Ok(())
    }

    #[tracing::instrument(name="app.stop", fields(id = %ShortId(&request.address)), skip_all)]
    async fn app_stop(&self, request: pb::Address) -> Result<()> {
        self.stop_app(request.decode_address()?).await?;
        Ok(())
    }

    async fn app_metrics(&self, request: pb::Addresses) -> Result<pb::AppMetricsResponse> {
        let addresses = request.decode_addresses()?;
        let addresses = if addresses.is_empty() {
            None
        } else {
            Some(&addresses[..])
        };
        let mut metrics = rpc::types::AppsMetrics {
            session: self.session().context("No worker session")?,
            nonce: rand::thread_rng().gen(),
            apps: vec![],
        };
        self.for_each_app(addresses, |address, app| {
            let m = app.metrics();
            metrics.apps.push(rpc::types::AppMetrics {
                address: address,
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
            load_or_generate_key().sign(wapod_signature::ContentType::Metrics, encoded_metrics);
        Ok(pb::AppMetricsResponse::new(metrics, signature))
    }

    #[tracing::instrument(name="app.resize", fields(id = %ShortId(&request.address)), skip_all)]
    async fn app_resize(&self, request: pb::ResizeArgs) -> Result<pb::Number> {
        info!(new_size = request.instances, "Resizing app");
        let address = request.decode_address()?;
        self.resize_app_instances(address, request.instances as usize, false)
            .await?;
        let number = self.num_instances_of(address).ok_or(RpcError::NotFound)?;
        Ok(pb::Number {
            value: number as u64,
        })
    }

    async fn app_list(&self) -> Result<pb::AppListResponse> {
        let apps = self
            .list()
            .into_iter()
            .map(|info| {
                pb::AppInfo::new(
                    info.sn,
                    info.address,
                    info.running_instances as _,
                    info.resizable,
                    info.start_mode,
                )
            })
            .collect();
        Ok(pb::AppListResponse { apps })
    }

    async fn apps_clear(&self) -> Result<()> {
        self.clear();
        Ok(())
    }

    async fn info(&self) -> Result<WorkerInfo> {
        UserRpc::info(self).await
    }
}

impl UserRpc for Call {
    async fn info(&self) -> Result<WorkerInfo> {
        Ok(Worker::info(self).await)
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
            error!(status_code, "prpc: Invalid status code!");
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

    info!("Dispatching request: {}", path);
    let result = server.dispatch_request(&path, data, json).await;
    let (code, data) = match result {
        Ok(data) => (200, data),
        Err(err) => {
            error!("Rpc error: {:?}", err);
            let (code, err) = match err {
                Error::NotFound => (404, ProtoError::new("Method Not Found")),
                Error::DecodeError(err) => (400, ProtoError::new(format!("DecodeError({err:?})"))),
                Error::BadRequest(msg) => (400, ProtoError::new(format!("BadRequest({msg:?})"))),
            };
            if json {
                let error = format!("{err:?}");
                let body = serde_json::to_string_pretty(&serde_json::json!({ "error": error }))
                    .unwrap_or_else(|_| r#"{"error": "Failed to encode the error"}"#.to_string())
                    .into_bytes();
                (code, body)
            } else {
                (code, pb::codec::encode_message_to_vec(&err))
            }
        }
    };
    (code, data)
}
