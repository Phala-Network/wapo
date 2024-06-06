use std::io::Read;

use hyper::body::Buf;
use log::info;
use wapo::net::hyper_v0::HttpConnector;

#[wapo::main]
async fn main() {
    wapo::logger::init();
    wapo::ocall::enable_ocall_trace(true).unwrap();

    let url = "https://example.com/";
    info!("Connecting to {}", url);
    let connector = HttpConnector::new();

    let client = hyper::Client::builder()
        .executor(wapo::hyper_rt::HyperExecutor)
        .build::<_, String>(connector);

    let response = client
        .get(url.parse().expect("Bad url"))
        .await
        .expect("Failed to send request");
    info!("response status: {}", response.status());

    let mut buf = vec![];
    hyper::body::aggregate(response)
        .await
        .expect("Failed to read response body")
        .reader()
        .read_to_end(&mut buf)
        .expect("Failed to read body");
    info!("body: {}", String::from_utf8_lossy(&buf));
}
