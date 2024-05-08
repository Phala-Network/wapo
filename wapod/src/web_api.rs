use phala_rocket_middleware::{RequestTracer, ResponseSigner, TimeMeter, TraceId};
use rocket::data::{ByteUnit, Limits, ToByteUnit};
use rocket::figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use rocket::fs::NamedFile;
use rocket::http::{ContentType, Method, Status};
use rocket::request::FromParam;
use rocket::response::status::Custom;
use rocket::{get, post, routes, Data, State};
use rocket_cors::{AllowedHeaders, AllowedMethods, AllowedOrigins, CorsOptions};
use tracing::{info, instrument, warn};

use sp_core::crypto::AccountId32;

use wapo_host::{crate_outgoing_request_channel, ShortId};
use wapod_rpc::prpc::blobs_server::BlobsServer;
use wapod_rpc::prpc::instances_server::InstancesServer;
use wapod_rpc::prpc::server::{ComposedService, Service};
use wapod_rpc::prpc::{admin_server::AdminServer, status_server::StatusServer};

use std::path::PathBuf;
use std::str::FromStr;

use service::Command;
use wapo_host::{
    rocket_stream::{connect, RequestInfo, StreamResponse},
    service, OutgoingRequest,
};

use crate::web_api::prpc_service::handle_prpc;
use crate::{worker_key, Args};

use app::App;

mod app;
mod prpc_service;

type UserService = ComposedService<App, (StatusServer<App>,)>;
type AdminService = ComposedService<
    App,
    (
        StatusServer<App>,
        AdminServer<App>,
        InstancesServer<App>,
        BlobsServer<App>,
    ),
>;

enum ReadDataError {
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

#[derive(Debug)]
struct HexBytes(pub Vec<u8>);
impl<'r> FromParam<'r> for HexBytes {
    type Error = &'static str;

    fn from_param(param: &str) -> Result<Self, Self::Error> {
        let param = param.trim_start_matches("0x");
        let bytes = hex::decode(param).map_err(|_| "Invalid hex string")?;
        Ok(HexBytes(bytes))
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

#[post("/push/query/<id>", data = "<data>")]
async fn push_query_no_origin(
    app: &State<App>,
    id: HexBytes,
    data: Data<'_>,
) -> Result<Vec<u8>, Custom<&'static str>> {
    push_query(app, id, None, data).await
}

#[post("/push/query/<id>/<origin>", data = "<data>")]
async fn push_query(
    app: &State<App>,
    id: HexBytes,
    origin: Option<&str>,
    data: Data<'_>,
) -> Result<Vec<u8>, Custom<&'static str>> {
    let payload = read_data(data, 100.mebibytes()).await?;
    let address =
        id.0.try_into()
            .map_err(|_| Custom(Status::BadRequest, "Invalid address"))?;

    let (reply_tx, rx) = tokio::sync::oneshot::channel();
    let origin = match origin {
        None => None,
        Some(origin) => Some(
            AccountId32::from_str(origin)
                .or(Err(Custom(
                    Status::BadRequest,
                    "Failed to decode the origin",
                )))?
                .into(),
        ),
    };

    app.send(
        address,
        Command::PushQuery {
            origin,
            payload,
            reply_tx,
        },
    )
    .await
    .map_err(|(code, reason)| Custom(Status { code }, reason))?;
    let reply = rx.await.or(Err(Custom(
        Status::InternalServerError,
        "Failed to receive query reply from the VM",
    )))?;
    Ok(reply)
}

#[post("/vm/<id>/<path..>", data = "<body>")]
async fn connect_vm_post<'r>(
    app: &State<App>,
    head: RequestInfo,
    id: HexBytes,
    path: PathBuf,
    body: Data<'r>,
) -> Result<StreamResponse, (Status, String)> {
    connect_vm(app, head, id, path, Some(body)).await
}

#[get("/vm/<id>/<path..>")]
async fn connect_vm_get<'r>(
    app: &State<App>,
    head: RequestInfo,
    id: HexBytes,
    path: PathBuf,
) -> Result<StreamResponse, (Status, String)> {
    connect_vm(app, head, id, path, None).await
}

async fn connect_vm<'r>(
    app: &State<App>,
    head: RequestInfo,
    id: HexBytes,
    path: PathBuf,
    body: Option<Data<'r>>,
) -> Result<StreamResponse, (Status, String)> {
    let address =
        id.0.try_into()
            .map_err(|_| (Status::BadRequest, "Invalid address".to_string()))?;
    let Some(command_tx) = app.sender_for(address) else {
        return Err((Status::NotFound, Default::default()));
    };
    let path = path
        .to_str()
        .ok_or((Status::BadRequest, "Invalid path".to_string()))?;
    let result = connect(head, path, body, command_tx).await;
    match result {
        Ok(response) => Ok(response),
        Err(err) => Err((Status::InternalServerError, err.to_string())),
    }
}

#[get("/info")]
async fn info(app: &State<App>) -> String {
    let info = app.info().await;
    serde_json::json!({
        "running": wapo_host::vm_count(),
        "deployed": info.running_instances,
    })
    .to_string()
}

#[instrument(target="prpc", name="prpc", fields(%id), skip_all)]
#[post("/<method>?<json>", data = "<data>")]
async fn prpc_post(
    app: &State<App>,
    id: TraceId,
    method: String,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Vec<u8>, Custom<Vec<u8>>> {
    let _ = id;
    handle_prpc::<UserService>(app, method, Some(data), limits, content_type, json).await
}

#[instrument(target="prpc", name="prpc", fields(%id), skip_all)]
#[get("/<method>")]
async fn prpc_get(
    app: &State<App>,
    id: TraceId,
    method: String,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Vec<u8>, Custom<Vec<u8>>> {
    let _ = id;
    handle_prpc::<UserService>(app, method, None, limits, content_type, true).await
}

#[instrument(target="prpc", name="prpc-admin", fields(%id), skip_all)]
#[post("/<method>?<json>", data = "<data>")]
async fn prpc_admin_post(
    app: &State<App>,
    id: TraceId,
    method: String,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Vec<u8>, Custom<Vec<u8>>> {
    let _ = id;
    handle_prpc::<AdminService>(app, method, Some(data), limits, content_type, json).await
}

#[instrument(target="prpc", name="prpc-admin", fields(%id), skip_all)]
#[get("/<method>")]
async fn prpc_admin_get(
    app: &State<App>,
    id: TraceId,
    method: String,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Vec<u8>, Custom<Vec<u8>>> {
    let _ = id;
    handle_prpc::<AdminService>(app, method, None, limits, content_type, true).await
}

#[post("/object/<hash>?<type>", data = "<data>")]
async fn object_post(
    app: &State<App>,
    limits: &Limits,
    r#type: &str,
    hash: HexBytes,
    data: Data<'_>,
) -> Result<(), Custom<String>> {
    let loader = app.blob_loader();
    let limit = limits.get("Admin.PutObject").unwrap_or(10.mebibytes());
    let mut stream = data.open(limit);
    match loader.put(&hash.0, &mut stream, r#type).await {
        Ok(()) => Ok(()),
        Err(err) => {
            warn!("Failed to put object: {err}");
            Err(Custom(Status::InternalServerError, err.to_string()))
        }
    }
}

#[get("/object/<id>")]
async fn object_get(app: &State<App>, id: HexBytes) -> Result<NamedFile, Custom<&'static str>> {
    let path = app.blob_loader().path(&id.0);
    NamedFile::open(&path)
        .await
        .map_err(|_| Custom(Status::NotFound, "Object not found"))
}

fn cors_options() -> CorsOptions {
    let allowed_methods: AllowedMethods = vec![Method::Get, Method::Post]
        .into_iter()
        .map(From::from)
        .collect();
    CorsOptions {
        allowed_origins: AllowedOrigins::all(),
        allowed_methods,
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }
}

fn sign_http_response(data: &[u8]) -> Option<String> {
    let pair = worker_key::load_or_generate_key();
    let signature = pair.sign(wapod_signature::ContentType::RpcResponse, data);
    Some(hex::encode(signature))
}

pub fn crate_app(args: Args) -> App {
    let (tx, mut rx) = crate_outgoing_request_channel();
    let (run, spawner) = service::service(args.workers, tx, &args.blobs_dir);
    tokio::spawn(async move {
        while let Some((id, message)) = rx.recv().await {
            let vmid = ShortId(id);
            match message {
                OutgoingRequest::Output(output) => {
                    info!(%vmid, "Outgoing message: {output:?}");
                }
            }
        }
    });
    std::thread::spawn(move || {
        run.blocking_run(|evt| {
            println!("event: {:?}", evt);
        });
    });
    App::new(spawner, args)
}

pub async fn serve_user(app: App) -> anyhow::Result<()> {
    print_rpc_methods("/prpc", &UserService::methods());
    let figment = Figment::from(rocket::Config::default())
        .merge(Toml::file("Wapod.toml").nested())
        .merge(Env::prefixed("WAPOD_USER_").global())
        .select("user");
    let signer = ResponseSigner::new(1024 * 1024 * 10, sign_http_response);
    let _rocket = rocket::custom(figment)
        .attach(cors_options().to_cors().expect("To not fail"))
        .attach(signer)
        .attach(RequestTracer::default())
        .attach(TimeMeter)
        .manage(app)
        .mount("/", routes![connect_vm_get, connect_vm_post])
        .mount("/prpc", routes![prpc_post, prpc_get])
        .launch()
        .await?;
    Ok(())
}

pub async fn serve_admin(app: App) -> anyhow::Result<()> {
    print_rpc_methods("/prpc", &AdminService::methods());
    let figment = Figment::from(rocket::Config::default())
        .merge(Toml::file("Wapod.toml").nested())
        .merge(Env::prefixed("WAPOD_ADMIN_").global())
        .select("admin");
    let _rocket = rocket::custom(figment)
        .attach(cors_options().to_cors().expect("To not fail"))
        .attach(RequestTracer::default())
        .attach(TimeMeter)
        .manage(app)
        .mount(
            "/",
            routes![
                push_query,
                push_query_no_origin,
                info,
                object_post,
                object_get,
            ],
        )
        .mount("/prpc", routes![prpc_admin_post, prpc_admin_get])
        .launch()
        .await?;
    Ok(())
}

fn print_rpc_methods(prefix: &str, methods: &[&str]) {
    info!("Methods under {}:", prefix);
    for method in methods {
        info!("    {}", format!("{prefix}/{method}"));
    }
}
