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
        if let Err(err) = query.reply_tx.send(b"Hello, World!") {
            error!("Failed to send reply: {:?}", err);
        }
    }
}
