use anyhow::{Context, Result};
use args::Args;
use hex_fmt::HexFmt;
use tracing::info;
use wapod::config::{DefaultWorkerConfig, KeyProvider, Paths, WorkerConfig};
use web_api::{serve_admin, serve_user};

type Config = DefaultWorkerConfig;
type Worker = wapod::Worker<Config>;

mod args;
mod logger;
mod web_api;

#[tokio::main]
async fn main() -> Result<()> {
    logger::init();

    info!("starting wapod server...");
    let args = Args::parse();

    info!("args: {:?}", args);

    args.validate().context("invalid args")?;

    Config::create_dirs_if_needed().context("failed to create directories")?;

    info!(
        "worker pubkey: 0x{}",
        HexFmt(<Config as WorkerConfig>::KeyProvider::get_key().public())
    );

    let worker = Worker::create_running(args.clone().into())
        .await
        .context("failed to create worker state")?;

    let admin_service = serve_admin(worker.clone(), args.clone());
    let user_service = async move {
        // Wait for the admin service to start
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        serve_user(worker, args).await
    };
    tokio::select! {
        result = user_service => {
            result.context("user service terminated")?;
        },
        result = admin_service => {
            result.context("admin service terminated")?;
        },
    }
    info!("server exited.");
    Ok(())
}

fn todo() {
    let todo = "Store instance logs to disk";
    let todo = "add prpc get worker description";
    let todo = "guest tip in metrics";

    let todo = "test signing with worker key for guest";
    let todo = "test sgx_quote api for guest";
    let todo = "test preemptive query instance";
    let todo = "tests for query signing";
    let todo = "whether the mr_enclave changes if signer changes?";
    let todo = "limit wasm blob size";
    let todo = "demo for quote/sign verification";
    let todo = "limit query time";
}
