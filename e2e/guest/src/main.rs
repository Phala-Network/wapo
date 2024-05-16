#![no_main]
use std::{fmt::Debug, time::Duration};

use log::{info, warn};
use wapo::channel::Query;

const INDEX: &[u8] = br#"Index:
    /
        => index page
    /echo
        => echo your request as response
    /helloworld
        => returns "Hello, world!"
    /sleep
        => sleep T before response a message where T is given via payload
"#;

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
            "/" => INDEX.to_vec(),
            "/echo" => query.payload,
            "/helloworld" => b"Hello, world!".to_vec(),
            "/sleep" => {
                handle_sleep(query);
                continue;
            }
            _ => b"404".to_vec(),
        };
        query.reply_tx.send(&reply).ignore();
    }
}

fn handle_sleep(query: Query) {
    wapo::spawn(async move {
        let reply = match String::from_utf8_lossy(&query.payload).parse() {
            Ok(ms) => {
                wapo::time::sleep(Duration::from_millis(ms)).await;
                format!("Slept {ms} ms").into_bytes()
            }
            Err(_) => b"Invalid timestamp".to_vec(),
        };
        query.reply_tx.send(&reply).ignore();
    });
}

trait Ignore {
    fn ignore(self);
}

impl<T, E: Debug> Ignore for Result<T, E> {
    fn ignore(self) {
        if let Err(err) = self {
            warn!("Ignored error: {err:?}");
        }
    }
}
