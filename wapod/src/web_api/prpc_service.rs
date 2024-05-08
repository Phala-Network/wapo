use anyhow::Context;
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
use rpc::prpc::{
    admin_server::AdminRpc, blobs_server::BlobsRpc, instances_server::InstancesRpc,
    status_server::StatusRpc,
};
use scale::Encode;
use tracing::{error, info, warn};
use wapod_rpc as rpc;

type Result<T, E = RpcError> = std::result::Result<T, E>;

use crate::worker_key::load_or_generate_key;

use super::{read_data, App};

impl AdminRpc for App {
    async fn exit(&self) -> Result<()> {
        std::process::exit(0);
    }
}

impl BlobsRpc for App {
    async fn put(&self, request: pb::Blob) -> Result<()> {
        let loader = self.blob_loader().await;
        loader
            .put(
                &request.hash,
                &mut &request.body[..],
                &request.hash_algrithm,
            )
            .await
            .map_err(|err| {
                warn!("Failed to put object: {err}");
                RpcError::BadRequest(format!("Failed to put object: {err}"))
            })
    }

    async fn exists(&self, request: pb::Blob) -> Result<pb::Boolean> {
        let loader = self.blob_loader().await;
        Ok(pb::Boolean {
            value: loader.exists(&request.hash),
        })
    }

    async fn remove(&self, request: pb::Blob) -> Result<()> {
        let loader = self.blob_loader().await;
        loader
            .remove(&request.hash)
            .map_err(|err| RpcError::BadRequest(format!("Failed to remove object: {err}")))
    }
}

impl InstancesRpc for App {
    async fn deploy(&self, request: pb::Manifest) -> Result<pb::Address> {
        let address = self
            .create_instance(request)
            .await
            .context("Failed to create instance")?;
        Ok(pb::Address {
            address: address.to_vec(),
        })
    }

    async fn remove(&self, request: pb::Address) -> Result<()> {
        self.remove_instance(request.decode_address()?).await?;
        Ok(())
    }

    async fn start(&self, request: pb::Address) -> Result<()> {
        self.start_instance(request.decode_address()?).await?;
        Ok(())
    }

    async fn stop(&self, request: pb::Address) -> Result<()> {
        self.stop_instance(request.decode_address()?).await?;
        Ok(())
    }

    async fn metrics(&self, request: pb::Addresses) -> Result<pb::InstanceMetricsResponse> {
        let todo = "TODO: implement session";
        let addresses = request.decode_addresses()?;
        let addresses = if addresses.is_empty() {
            None
        } else {
            Some(&addresses[..])
        };
        let mut metrics = vec![];
        self.for_each_instance(addresses, |address, instance| {
            let m = instance.metrics();
            metrics.push(pb::InstanceMetrics {
                address: address.encode(),
                session: vec![],
                running_time_ms: m.duration.as_millis() as u64,
                gas_consumed: m.gas_comsumed,
                network_ingress: m.net_ingress,
                network_egress: m.net_egress,
                storage_read: m.storage_read,
                storage_write: m.storage_written,
                starts: m.starts,
            });
        })
        .await;
        let encoded_metrics = metrics.encode();
        let signature =
            load_or_generate_key().sign(wapod_signature::ContentType::Metrics, encoded_metrics);
        Ok(pb::InstanceMetricsResponse { metrics, signature })
    }
}

impl StatusRpc for App {
    async fn info(&self) -> Result<WorkerInfo> {
        Ok(App::info(self).await)
    }
}

pub async fn handle_prpc<S>(
    app: &State<App>,
    method: String,
    data: Option<Data<'_>>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Vec<u8>, Custom<Vec<u8>>>
where
    S: From<App> + PrpcService,
{
    let data = match data {
        Some(data) => {
            let limit = limit_for_method(&method, limits);
            read_data(data, limit).await?
        }
        None => vec![],
    };
    let json = json || content_type.map(|t| t.is_json()).unwrap_or(false);
    let app = (*app).clone();
    let data = data.to_vec();
    let result = dispatch_prpc(method, data, json, S::from(app)).await;
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
