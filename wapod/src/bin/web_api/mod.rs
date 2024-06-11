use anyhow::{Context, Result};
use phala_rocket_middleware::{RequestTracer, ResponseSigner, TimeMeter, TraceId};
use rocket::data::{Limits, ToByteUnit};
use rocket::figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use rocket::fs::NamedFile;
use rocket::http::{ContentType, Method, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::response::content::RawHtml;
use rocket::response::status::Custom;
use rocket::response::Redirect;
use rocket::{get, post, routes, Data, Request, State};
use rocket_cors::{AllowedHeaders, AllowedMethods, AllowedOrigins, CorsOptions};
use tracing::{info, instrument, warn};
use wapod::config::WorkerConfig;

use std::path::PathBuf;
use wapod_rpc::prpc::server::Service;

use wapo_host::rocket_stream::{RequestInfo, StreamResponse};

use wapod::config::KeyProvider;
use wapod::prpc_service::{connect_vm, handle_prpc, HexBytes};

use crate::{Args, Config, Worker};

type UserService = wapod::prpc_service::UserService<Config>;
type AdminService = wapod::prpc_service::AdminService<Config>;

use auth::Authorized;

mod auth;

struct NoEndSlash;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for NoEndSlash {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if request.uri().path().as_str().ends_with('/') {
            Outcome::Forward(Status::NotFound)
        } else {
            Outcome::Success(NoEndSlash)
        }
    }
}

#[post("/app/<id>", rank = 1)]
async fn redirect_connect_vm_post(id: &str, _guard: NoEndSlash) -> Redirect {
    Redirect::permanent(format!("/app/{}/", id))
}

#[get("/app/<id>", rank = 1)]
async fn redirect_connect_vm_get(id: &str, _guard: NoEndSlash) -> Redirect {
    Redirect::permanent(format!("/app/{}/", id))
}

#[post("/app/<id>/<path..>", data = "<body>", rank = 2)]
async fn connect_vm_post<'r>(
    state: &State<Worker>,
    head: RequestInfo,
    id: HexBytes,
    path: PathBuf,
    body: Data<'r>,
) -> Result<StreamResponse, (Status, String)> {
    connect_vm(state, head, id, path, Some(body)).await
}

#[get("/app/<id>/<path..>", rank = 2)]
async fn connect_vm_get<'r>(
    state: &State<Worker>,
    head: RequestInfo,
    id: HexBytes,
    path: PathBuf,
) -> Result<StreamResponse, (Status, String)> {
    connect_vm(state, head, id, path, None).await
}

#[instrument(target="prpc", name="user", fields(%id), skip_all)]
#[post("/<method>?<json>", data = "<data>")]
async fn prpc_post(
    state: &State<Worker>,
    id: TraceId,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Vec<u8>, Custom<Vec<u8>>> {
    let _ = id;
    handle_prpc::<UserService, _>(state, method, Some(data), limits, content_type, json).await
}

#[instrument(target="prpc", name="user", fields(%id), skip_all)]
#[get("/<method>")]
async fn prpc_get(
    state: &State<Worker>,
    id: TraceId,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Vec<u8>, Custom<Vec<u8>>> {
    let _ = id;
    handle_prpc::<UserService, _>(state, method, None, limits, content_type, true).await
}

#[allow(clippy::too_many_arguments)]
#[instrument(target="prpc", name="admin", fields(%id), skip_all)]
#[post("/<method>?<json>", data = "<data>")]
async fn prpc_admin_post(
    _auth: Authorized,
    state: &State<Worker>,
    id: TraceId,
    limits: &Limits,
    content_type: Option<&ContentType>,
    method: &str,
    data: Data<'_>,
    json: bool,
) -> Result<Vec<u8>, Custom<Vec<u8>>> {
    let _ = id;
    handle_prpc::<AdminService, _>(state, method, Some(data), limits, content_type, json).await
}

#[instrument(target="prpc", name="admin", fields(%id), skip_all)]
#[get("/<method>")]
async fn prpc_admin_get(
    _auth: Authorized,
    state: &State<Worker>,
    id: TraceId,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Vec<u8>, Custom<Vec<u8>>> {
    let _ = id;
    handle_prpc::<AdminService, _>(state, method, None, limits, content_type, true).await
}

#[post("/blob/<hash>?<type>", data = "<data>")]
async fn blob_post(
    _auth: Authorized,
    state: &State<Worker>,
    limits: &Limits,
    r#type: &str,
    hash: HexBytes,
    data: Data<'_>,
) -> Result<Vec<u8>, Custom<String>> {
    let loader = state.blob_loader();
    let limit = limits.get("Admin.PutObject").unwrap_or(10.mebibytes());
    let mut stream = data.open(limit);
    loader
        .put(&hash.0, &mut stream, r#type)
        .await
        .map_err(|err| {
            warn!("failed to put object: {err:?}");
            Custom(Status::InternalServerError, err.to_string())
        })
}

#[get("/blob/<id>")]
async fn blob_get(
    _auth: Authorized,
    state: &State<Worker>,
    id: HexBytes,
) -> Result<NamedFile, Custom<&'static str>> {
    let path = state.blob_loader().path(&id.0);
    NamedFile::open(&path)
        .await
        .map_err(|_| Custom(Status::NotFound, "Object not found"))
}

#[get("/")]
async fn console() -> RawHtml<&'static str> {
    RawHtml(include_str!("console.html"))
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

fn sign_http_response<K: KeyProvider>(data: &[u8]) -> Option<String> {
    let signature = K::get_key().sign(wapod_crypto::ContentType::RpcResponse, data);
    Some(hex::encode(signature))
}

pub async fn serve_user(state: Worker, args: Args) -> Result<()> {
    print_rpc_methods("/prpc", &UserService::methods());
    let mut figment = Figment::from(rocket::Config::default())
        .merge(Toml::file("Wapod.toml").nested())
        .merge(Env::prefixed("WAPOD_USER_").global())
        .select("user");
    if let Some(user_port) = args.user_port {
        figment = figment.merge(("port", user_port));
    }
    let signer = ResponseSigner::new(
        1024 * 1024 * 10,
        sign_http_response::<<Config as WorkerConfig>::KeyProvider>,
    );
    let _rocket = rocket::custom(figment)
        .attach(
            cors_options()
                .to_cors()
                .context("failed to create CORS options")?,
        )
        .attach(signer)
        .attach(RequestTracer::default())
        .attach(TimeMeter)
        .manage(state)
        .mount(
            "/",
            routes![
                connect_vm_get,
                connect_vm_post,
                redirect_connect_vm_get,
                redirect_connect_vm_post
            ],
        )
        .mount("/prpc", routes![prpc_post, prpc_get])
        .launch()
        .await?;
    Ok(())
}

pub async fn serve_admin(state: Worker, args: Args) -> Result<()> {
    print_rpc_methods("/prpc", &AdminService::methods());
    let mut figment = Figment::from(rocket::Config::default())
        .merge(Toml::file("Wapod.toml").nested())
        .merge(Env::prefixed("WAPOD_ADMIN_").global())
        .select("admin");
    if let Some(admin_port) = args.admin_port {
        figment = figment.merge(("port", admin_port));
    }
    let _rocket = rocket::custom(figment)
        .attach(
            cors_options()
                .to_cors()
                .context("failed to create CORS options")?,
        )
        .attach(RequestTracer::default())
        .attach(TimeMeter)
        .manage(auth::ApiToken::new(args.admin_api_token))
        .manage(state)
        .mount("/", routes![blob_post, blob_get, console])
        .mount("/prpc", routes![prpc_admin_post, prpc_admin_get])
        .launch()
        .await?;
    Ok(())
}

fn print_rpc_methods(prefix: &str, methods: &[&str]) {
    info!("methods under {}:", prefix);
    for method in methods {
        info!("    {}", format!("{prefix}/{method}"));
    }
}
