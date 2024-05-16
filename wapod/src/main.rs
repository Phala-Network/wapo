use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use web_api::crate_worker_state;

mod logger;
mod paths;
mod web_api;
mod worker_key;
mod allocator;

#[derive(Parser, Clone)]
#[clap(about = "wapo - a WASM runtime", version, author)]
pub struct Args {
    /// Max memory pages
    #[arg(long, default_value_t = 256)]
    max_memory_pages: u32,
    /// Max number of instances to run
    #[arg(long, default_value_t = 8)]
    max_instances: u32,
    /// Path to store hash blobs
    #[arg(long, default_value = "./blobs")]
    blobs_dir: String,
    /// The port that admin service listens on
    #[arg(long)]
    admin_port: Option<u16>,
    /// The port that user service listens on
    #[arg(long)]
    user_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    logger::init();

    info!("Starting wapod server...");
    let args = Args::parse();

    paths::create_dirs_if_needed().context("Failed to create directories")?;

    let key = worker_key::load_or_generate_key().public();
    info!("Worker pubkey: 0x{}", hex_fmt::HexFmt(key));

    let worker_state = crate_worker_state(args.clone()).context("Failed to create worker state")?;
    let admin_service = web_api::serve_admin(worker_state.clone(), args.clone());
    let user_service = async move {
        // Wait for the admin service to start
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        web_api::serve_user(worker_state, args).await
    };
    tokio::select! {
        result = user_service => {
            result.context("User service terminated")?;
        },
        result = admin_service => {
            result.context("Admin service terminated")?;
        },
    }
    info!("Server exited.");
    Ok(())
}

fn todo() {
    let todo = "Validate max_memory_pages * max_instances < WAPOD_ENCLAVE_MEM_SIZE";
    let todo = "Store instance logs to disk";
    let todo = "implement JWT auth";
    let todo = "put RUST_LOG_SANITIZED in grame manifest";
}
