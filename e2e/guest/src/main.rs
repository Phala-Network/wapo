#![no_main]
use std::time::Duration;

use log::{error, info};

#[wapo::main]
async fn main() {
    use wapo::logger::{LevelFilter, Logger};
    Logger::with_max_level(LevelFilter::Info).init();

    info!("Started!");
    let ch = wapo::channel::incoming_queries();
    loop {
        info!("Waiting for query...");
        let Some(query) = ch.next().await else {
            break;
        };
        info!("Received query: {:?}", query.path);
        let reply = match query.path.as_str() {
            "/echo" => query.payload,
            "/helloworld" => b"Hello, world!".to_vec(),
            "/sleep" => handle_sleep(query.payload).await,
            _ => b"404".to_vec(),
        };
        if let Err(err) = query.reply_tx.send(&reply) {
            error!("Failed to send reply: {:?}", err);
        }
    }
}

async fn handle_sleep(data: Vec<u8>) -> Vec<u8> {
    match String::from_utf8_lossy(&data).parse() {
        Ok(ms) => {
            wapo::time::sleep(Duration::from_millis(ms)).await;
            format!("Slept {ms} ms").into_bytes()
        }
        Err(_) => b"Invalid timestamp".to_vec(),
    }
}
