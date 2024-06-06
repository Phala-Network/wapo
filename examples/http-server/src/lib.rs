use log::info;
use std::convert::Infallible;

use hyper::{server::conn::http1, service::service_fn, Request, Response};
use wapo::{env::tls::TlsServerConfig, hyper_rt::HyperTokioIo};

const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBZzCCAQ2gAwIBAgIIbELHFTzkfHAwCgYIKoZIzj0EAwIwITEfMB0GA1UEAwwW
cmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAwMDBaGA80MDk2MDEw
MTAwMDAwMFowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABOoRzdEagFDZf/im79Z5JUyeXP96Yww6nH8X
ROvXOESnE0yFtlVjdj0NTNXT2m+PWzuxsjvPVBWR/tpDldjTW8CjLTArMCkGA1Ud
EQQiMCCCE2hlbGxvLndvcmxkLmV4YW1wbGWCCWxvY2FsaG9zdDAKBggqhkjOPQQD
AgNIADBFAiEAsuZKsdksPsrnJFdV9JTZ1P782IlqjqNL9aAURvrF3UkCIDDpTvE5
EyZ5zRflnB+ZwomjXNhTAnasRjQTDqXFrQbP
-----END CERTIFICATE-----";

const KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgH1VlVX/3DI37UR5g
tGzUOSAaOmjQbZMJQ2Z9eBnzh3+hRANCAATqEc3RGoBQ2X/4pu/WeSVMnlz/emMM
Opx/F0Tr1zhEpxNMhbZVY3Y9DUzV09pvj1s7sbI7z1QVkf7aQ5XY01vA
-----END PRIVATE KEY-----";

async fn handle(request: Request<hyper::body::Incoming>) -> Result<Response<String>, Infallible> {
    info!("Incoming request: {}", request.uri().path());
    Ok(Response::new("Hello, World!\n".into()))
}

#[wapo::main]
async fn main() -> anyhow::Result<()> {
    wapo::logger::init();
    wapo::ocall::enable_ocall_trace(true).unwrap();

    let address = "0.0.0.0:1999";
    info!("Listening on https://{}", address);

    let listener = wapo::net::TcpListener::bind_tls(
        address,
        TlsServerConfig::V0 {
            cert: CERT.to_string(),
            key: KEY.to_string(),
        },
    )
    .await
    .unwrap();

    loop {
        let (stream, _) = listener.accept().await?;
        wapo::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(HyperTokioIo::new(stream), service_fn(handle))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
