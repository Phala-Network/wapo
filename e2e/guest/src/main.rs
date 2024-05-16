#![no_main]
use std::{fmt::Debug, time::Duration};

use anyhow::{Context, Result};
use log::{info, warn};

#[wapo::main]
async fn main() {
    use wapo::logger::{LevelFilter, Logger};
    Logger::with_max_level(LevelFilter::Info).init();

    info!("Started!");
    let query_rx = wapo::channel::incoming_queries();
    loop {
        info!("Waiting for query...");
        let Some(query) = query_rx.next().await else {
            break;
        };
        info!("Received query: {:?}", query.path);
        if query.path == "/return" {
            break;
        }
        wapo::spawn(async move {
            let result = handle_query(query.path, query.payload).await;
            let reply = match result {
                Ok(reply) => reply,
                Err(err) => format!("QueryError: {err:?}").into_bytes(),
            };
            query.reply_tx.send(&reply).ignore();
        });
    }
}

const INDEX: &[u8] = br#"Index:
    /
        => index page
    /echo
        => echo your request as response
    /helloworld
        => returns "Hello, world!"
    /sleep
        => sleep T before response a message where T is given via payload
    /exit
        => exit the program with the given code
    /return
        => return the main function
"#;

async fn handle_query(path: String, payload: Vec<u8>) -> Result<Vec<u8>> {
    let reply = match path.as_str() {
        "/" => INDEX.to_vec(),
        "/echo" => payload,
        "/helloworld" => b"Hello, world!".to_vec(),
        "/sleep" => handle_sleep(&payload).await?,
        "/exit" => handle_exit(&payload)?,
        _ => b"404".to_vec(),
    };
    Ok(reply)
}

async fn handle_sleep(data: &[u8]) -> Result<Vec<u8>> {
    let ms = String::from_utf8_lossy(data)
        .parse()
        .context("Invalid time")?;
    wapo::time::sleep(Duration::from_millis(ms)).await;
    Ok(format!("Slept {ms} ms").into_bytes())
}

fn handle_exit(data: &[u8]) -> Result<Vec<u8>> {
    let code = String::from_utf8_lossy(data)
        .parse()
        .context("Invalid time")?;
    std::process::exit(code);
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
