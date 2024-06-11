use anyhow::{Context, Result};
use hyper::{body::Bytes, Request};
use log::{error, info};
use std::sync::Arc;

use http_body_util::{BodyExt, Empty};

use tokio_rustls::{rustls, TlsConnector};
use wapo::{hyper_rt::HyperTokioIo, net::TcpStream};

async fn fetch_url(url: hyper::Uri) -> Result<()> {
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(443);

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let domain = rustls_pki_types::ServerName::try_from(host)
        .context("invalid dnsname")?
        .to_owned();

    let tcp_stream = TcpStream::connect(host, port, false).await?;
    let tls_stream = connector
        .connect(domain, tcp_stream)
        .await
        .context("TLS handshake failed")?;

    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(HyperTokioIo::new(tls_stream)).await?;
    wapo::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {:?}", err);
        }
    });

    let authority = url.authority().unwrap().clone();

    let path = url.path();
    let req = Request::builder()
        .uri(path)
        .header(hyper::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())?;

    let mut res = sender.send_request(req).await?;

    info!("Response: {}", res.status());
    info!("Headers: {:#?}\n", res.headers());

    // Stream the body, writing each chunk to stdout as we get it
    // (instead of buffering and printing at the end).
    while let Some(next) = res.frame().await {
        let data = next?.into_data().ok().context("Invalid chunk")?;
        let chunk = String::from_utf8_lossy(&data);
        info!("Chunk: {}", chunk);
    }

    info!("\n\nDone!");

    Ok(())
}

#[wapo::main]
async fn main() -> Result<()> {
    wapo::logger::init();

    let url = "https://example.com".parse().expect("Bad url");
    info!("Fetching {url:?}");
    fetch_url(url).await
}
