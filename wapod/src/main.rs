use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};
use web_api::crate_worker_state;

mod allocator;
mod logger;
mod paths;
mod web_api;
mod worker_key;

#[derive(Parser, Clone, Debug)]
#[clap(about = "wapo - a WASM runtime", version, author)]
pub struct Args {
    /// Max memory pages
    #[arg(long, default_value_t = 256)]
    max_memory_pages: usize,
    /// Max number of instances to run
    #[arg(long)]
    max_instances: Option<usize>,
    /// Path to store hash blobs
    #[arg(long, default_value = "./blobs")]
    blobs_dir: String,
    /// The port that admin service listens on
    #[arg(long)]
    admin_port: Option<u16>,
    /// The port that user service listens on
    #[arg(long)]
    user_port: Option<u16>,
    /// Number of modules can be stored in the LRU cache
    #[arg(long, default_value_t = 16)]
    module_cache_size: usize,
}

impl Args {
    fn max_instances(&self) -> usize {
        self.max_instances
            .unwrap_or_else(|| self.max_allowed_instances().unwrap_or(32))
    }

    fn validate(&self) -> Result<()> {
        self.validate_mem_size()?;
        Ok(())
    }

    fn max_allowed_instances(&self) -> Option<usize> {
        let enclave_size = enclave_size()?;
        let page_size = 64 * 1024;
        let est_sys_overhead = 1024 * 1024 * 256;
        let est_vm_overhead = 1024 * 1024;
        let memory_per_vm = self
            .max_memory_pages
            .max(1)
            .saturating_mul(page_size)
            .saturating_add(est_vm_overhead);
        let allowed_instances = enclave_size
            .saturating_sub(est_sys_overhead)
            .saturating_div(memory_per_vm);
        Some(allowed_instances)
    }

    fn validate_mem_size(&self) -> Result<()> {
        let Some(allowed_instances) = self.max_allowed_instances() else {
            warn!("WAPOD_ENCLAVE_MEM_SIZE is not set, skipping validation");
            return Ok(());
        };
        if let Some(enclave_size) = enclave_size() {
            info!("enclave size: {enclave_size}");
        }
        info!("possible instances: {allowed_instances}");
        info!("set max instances: {}", self.max_instances());
        if self.max_instances() > allowed_instances {
            anyhow::bail!("max_instances is too large");
        }
        Ok(())
    }
}

fn enclave_size() -> Option<usize> {
    let Ok(enclave_mem_size) = std::env::var("WAPOD_ENCLAVE_MEM_SIZE") else {
        return None;
    };
    let enclave_mem_size: usize = enclave_mem_size
        .parse()
        .expect("WAPOD_ENCLAVE_MEM_SIZE must be an integer");
    Some(enclave_mem_size)
}

#[tokio::main]
async fn main() -> Result<()> {
    logger::init();

    info!("starting wapod server...");
    let args = Args::parse();

    info!("args: {:?}", args);

    args.validate().context("invalid args")?;

    paths::create_dirs_if_needed().context("failed to create directories")?;

    let key = worker_key::load_or_generate_key().public();
    info!("worker pubkey: 0x{}", hex_fmt::HexFmt(key));

    let worker_state = crate_worker_state(args.clone()).context("failed to create worker state")?;
    let admin_service = web_api::serve_admin(worker_state.clone(), args.clone());
    let user_service = async move {
        // Wait for the admin service to start
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        web_api::serve_user(worker_state, args).await
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
    let todo = "implement JWT auth";
    let todo = "put RUST_LOG_SANITIZED/WAPOD_ENCLAVE_MEM_SIZE in grame manifest";
    let todo = "add prpc register_info";
    let todo = "implement signing with worker key for guest";
    let todo = "implement sgx_quote api for guest";
}
