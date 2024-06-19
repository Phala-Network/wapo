use std::{convert::Infallible, sync::Arc};

use anyhow::{bail, Context, Result};
use hyper::{body::Incoming, service::service_fn, Request, Response};
use log::{error, info};
use rustls_pemfile::Item;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use wapo::net::TcpListener;

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

fn load_certs(pem_str: &str) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut pem_str.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid certificate")
}

fn load_private_key(pem_str: &str) -> Result<PrivateKeyDer<'static>> {
    let key = rustls_pemfile::read_all(&mut pem_str.as_bytes())
        .next()
        .context("No key found")?
        .context("Invalid key")?;
    let key = match key {
        Item::Pkcs1Key(key) => PrivateKeyDer::Pkcs1(key),
        Item::Pkcs8Key(key) => PrivateKeyDer::Pkcs8(key),
        Item::Sec1Key(key) => PrivateKeyDer::Sec1(key),
        _ => bail!("Invalid key"),
    };
    Ok(key)
}

async fn handle(_request: Request<Incoming>) -> Result<Response<String>, Infallible> {
    info!("Request received");
    Ok(Response::new("Hello, World!\n".to_string()))
}

#[wapo::main]
async fn main() -> Result<()> {
    wapo::logger::init();

    let address = "127.0.0.1:1999";
    let certs = load_certs(CERT)?;
    let key = load_private_key(KEY)?;

    let mut cert_resolver = rustls::server::ResolvesServerCertUsingSni::new();

    let certified_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
    // Select a certificate based on the SNI value.
    cert_resolver
        .add(
            "localhost",
            rustls::sign::CertifiedKey::new(certs.clone(), certified_key),
        )
        .context("Failed to add certificate")?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(cert_resolver));
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(address).await?;
    log::info!("Listening on https://{}", address);
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!("Incomming connection from {peer_addr:?}");
        let acceptor = acceptor.clone();

        let fut = async move {
            let stream = acceptor.accept(stream).await?;
            let Some(server_name) = stream.get_ref().1.server_name() else {
                bail!("No server name");
            };
            // App can dispatch the connection to correct handler based on server_name
            match server_name {
                "localhost" => {
                    info!("TLS connection established with localhost");
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            wapo::hyper_rt::HyperTokioIo::new(stream),
                            service_fn(handle),
                        )
                        .await
                    {
                        error!("Error serving connection: {:?}", err);
                    }
                }
                _ => {
                    error!("Unknown server name: {server_name:?}");
                }
            }
            Ok(()) as Result<()>
        };

        wapo::spawn(async move {
            if let Err(err) = fut.await {
                error!("Error while hanlding request: {err:?}");
            }
        });
    }
}
