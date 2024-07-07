use anyhow::{bail, Result};
use futures::stream::FuturesUnordered;
use futures::StreamExt as _;
use log::{debug, info};
use serde::Serialize;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc::Sender;

use wapo::env::MetricsToken;
use wapod_types::bench_app::{SignedMessage, SigningMessage};
use wapod_types::scale::Encode;

#[derive(Default, Debug, Serialize)]
struct BenchScore {
    gas_per_second: u64,
    gas_consumed: u64,
    timestamp_secs: u64,
    #[serde(skip)]
    metrics_token: MetricsToken,
}

struct State {
    score: BenchScore,
}

pub async fn query_serve() {
    let query_rx = wapo::channel::incoming_queries();

    let (score_tx, mut score_rx) = tokio::sync::mpsc::channel(1);
    wapo::spawn(score_update(score_tx));

    let mut state = State {
        score: BenchScore::default(),
    };

    loop {
        tokio::select! {
            query = query_rx.next() => {
                let Some(query) = query else {
                    break;
                };
                match handle_query(&mut state, query.path, query.payload).await {
                    Ok(reply) => {
                        _ = query.reply_tx.send(&reply);
                    }
                    Err(e) => {
                        _ = query.reply_tx.send_error(&e.to_string());
                    }
                }
            }
            score = score_rx.recv() => {
                let Some(score) = score else {
                    info!("score channel closed");
                    break;
                };
                state.score = score;
            }
        }
    }
}

async fn score_update(tx: Sender<BenchScore>) {
    loop {
        let net_start_time = net_now().await;
        let local_start_time = Instant::now();
        let (gas_at_start, _) =
            wapo::ocall::app_gas_consumed().expect("failed to get gas consumed");
        debug!("net_start_time: {:?}", net_start_time);
        debug!("gas_at_start: {:?}", gas_at_start);
        wapo::time::sleep(Duration::from_secs(30)).await;
        let (gas_at_end, token) =
            wapo::ocall::app_gas_consumed().expect("failed to get gas consumed");
        let local_elapsed = local_start_time.elapsed();
        let net_end_time = net_now().await;
        debug!("net_end_time: {:?}", net_end_time);
        debug!("gas_at_end: {:?}", gas_at_end);
        match (&net_start_time, &net_end_time) {
            (Ok(start_time), Ok(end_time)) => {
                let Ok(net_elapsed) = end_time.duration_since(*start_time) else {
                    info!("invalid net time, skipping score update");
                    continue;
                };
                let diff = local_elapsed.as_secs_f64() - net_elapsed.as_secs_f64();
                if diff.abs() > 10_f64 {
                    info!("time diff between local and net is too large: {diff}");
                    continue;
                }
                let gas_diff = gas_at_end.saturating_sub(gas_at_start);
                let score = gas_diff.saturating_div(local_elapsed.as_secs());
                debug!("score: {:?}", score);
                let score = BenchScore {
                    gas_per_second: score,
                    gas_consumed: gas_at_end,
                    timestamp_secs: end_time
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .expect("failed to get timestamp")
                        .as_secs(),
                    metrics_token: token,
                };
                tx.send(score).await.expect("failed to send score");
            }
            _ => {
                info!("failed to get net time, skipping score update");
            }
        }
    }
}

async fn net_now() -> Result<SystemTime> {
    let servers = [
        "https://www.cloudflare.com",
        "https://www.apple.com",
        "https://www.baidu.com",
        "https://kernel.org/",
    ];

    let mut futures = FuturesUnordered::new();
    for server in servers {
        futures.push(httptime::get_time(server, Duration::from_secs(2)));
    }
    loop {
        let Some(result) = futures.next().await else {
            bail!("all servers failed");
        };
        if let Ok(time) = result {
            return Ok(time);
        }
    }
}

async fn handle_query(state: &mut State, path: String, _payload: Vec<u8>) -> Result<Vec<u8>> {
    match path.as_str() {
        "/score" => serde_json::to_vec(&state.score)
            .map_err(|e| anyhow::anyhow!("failed to serialize score: {}", e)),
        "/signedScore" => {
            let score = &state.score;
            let message = SigningMessage::BenchScore {
                gas_per_second: score.gas_per_second,
                timestamp_secs: score.timestamp_secs,
                gas_consumed: score.gas_consumed,
                matrics_token: score.metrics_token.clone(),
            };
            let encoded_message = message.encode();
            let signature = wapo::ocall::sign(&encoded_message)
                .expect("ocall::sign never fails")
                .into();
            let address = wapo::ocall::app_address().expect("failed to get app address");
            let worker_pubkey = wapo::ocall::worker_pubkey().expect("failed to get worker pubkey");
            let signed_message = SignedMessage {
                message,
                signature,
                worker_pubkey,
                app_address: address,
            };
            Ok(signed_message.encode())
        }
        _ => {
            bail!("unknown path: {}", path);
        }
    }
}
