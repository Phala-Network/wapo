#![no_main]
use std::{fmt::Debug, time::Duration};

use anyhow::{Context, Result};
use log::{info, warn};

use tokio::io::AsyncWriteExt;

use wapo::env::messages::HttpResponseHead;

#[wapo::main]
async fn main() {
    use wapo::logger::{LevelFilter, Logger};
    Logger::with_max_level(LevelFilter::Info).init();

    info!("started!");
    let query_rx = wapo::channel::incoming_queries();
    let connection_listener = wapo::channel::incoming_http_connections();
    loop {
        info!("waiting for requests...");
        tokio::select! {
            query = query_rx.next() => {
                let Some(query) = query else {
                    break;
                };
                info!("received query: {:?}", query.path);
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
            },
            http = connection_listener.next() => {
                let Some(mut conn) = http else {
                    break;
                };
                info!("received http connection: {} {}", conn.head.method, conn.head.url);
                wapo::spawn(async move {
                    if let Err(err) = conn.response_tx.send(HttpResponseHead { status: 200, headers: vec![] }) {
                        warn!("failed to send response head: {err}");
                        return;
                    }
                    for i in 0..10 {
                        info!("sending: {i}");
                        let message = format!("{i}\n");
                        if let Err(err)  = conn.io_stream.write_all(message.as_bytes()).await {
                            warn!("failed to send message: {err}");
                            break;
                        }
                        wapo::time::sleep(Duration::from_secs(1)).await;
                    }
                    info!("finished handling http connection");
                });

            },
        }
    }
}

const INDEX: &[u8] = br#"Index:
    /
        => index page
    /echo
        => echo your request as response
    /sleep
        => sleep T before response a message where T is given via payload
    /exit
        => exit the program with the given code
    /return
        => return the main function
    /alloc
        => test memory allocation
"#;

async fn handle_query(path: String, payload: Vec<u8>) -> Result<Vec<u8>> {
    let parts: Vec<_> = path.split('/').skip(1).collect();
    let reply = match &parts[..] {
        [""] => INDEX.to_vec(),
        ["echo"] => payload,
        ["sleep", v] => handle_sleep(v).await?,
        ["exit", v] => handle_exit(v)?,
        ["alloc", v] => handel_alloc(v)?,
        _ => b"404".to_vec(),
    };
    Ok(reply)
}

fn handel_alloc(data: &str) -> Result<Vec<u8>> {
    let size: usize = parse_size::parse_size(data).context("invalid size")? as _;
    const MB: usize = 1024 * 1024;
    if size < 16 * MB {
        let tmp = vec![1u8; size];
        info!("allocated: {}", tmp.len());
    } else {
        let mut alloced = vec![];
        for i in 1.. {
            alloced.push(vec![1u8; MB * 16]);
            let alloced_size = MB * 16 * i;
            info!("allocated: {alloced_size}");
            if alloced_size >= size {
                break;
            }
        }
    }
    Ok(b"allocated".to_vec())
}

async fn handle_sleep(data: &str) -> Result<Vec<u8>> {
    let ms = data.parse().context("invalid time")?;
    wapo::time::sleep(Duration::from_millis(ms)).await;
    Ok(format!("Slept {ms} ms").into_bytes())
}

fn handle_exit(data: &str) -> Result<Vec<u8>> {
    let code = data.parse().context("invalid time")?;
    std::process::exit(code);
}

trait Ignore {
    fn ignore(self);
}

impl<T, E: Debug> Ignore for Result<T, E> {
    fn ignore(self) {
        if let Err(err) = self {
            warn!("ignored error: {err:?}");
        }
    }
}
