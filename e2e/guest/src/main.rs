#![no_main]
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
            _ => b"404".to_vec(),
        };
        if let Err(err) = query.reply_tx.send(&reply) {
            error!("Failed to send reply: {:?}", err);
        }
    }
}
