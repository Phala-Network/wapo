use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};
use web_api::crate_worker_state;

mod allocator;
mod logger;
mod paths;
mod sgx;
mod web_api;
mod worker_key;

#[derive(Parser, Clone, Debug)]
#[clap(about = "wapod - a WASM runtime", version, author)]
pub struct Args {
    /// Maximum memory size for each instance.
    #[arg(long, short='m', default_value = "128M", value_parser = parse_size)]
    instance_memory_size: u64,

    /// Maximum number of instances to run. If not specified, it will be determined by the enclave
    /// size and instance memory size.
    #[arg(long, short='c', default_value_t = 8)]
    max_instances: usize,

    /// Port number for the admin service to listen on. If not specified, the value will be
    /// read from the configuration file.
    #[arg(long)]
    admin_port: Option<u16>,

    /// API token required for accessing the admin service. If empty, no token is required.
    /// When provided, the token must be included in the `Authorization: Bearer` header for
    /// each incoming request.
    #[arg(long, short='t', default_value_t = String::new())]
    admin_api_token: String,

    /// Port number for the user service to listen on. If not specified, the value will be
    /// read from the configuration file.
    #[arg(long)]
    user_port: Option<u16>,

    /// Number of compiled WebAssembly modules that can be cached (default: 16).
    #[arg(long, default_value_t = 16)]
    module_cache_size: usize,

    /// Disable memory pool for instances.
    #[arg(long)]
    no_mem_pool: bool,
}

impl Args {
    fn max_instances(&self) -> usize {
        self.max_instances
    }

    fn validate(&self) -> Result<()> {
        self.validate_mem_size()?;
        Ok(())
    }

    fn max_allowed_instances(&self) -> Option<usize> {
        let enclave_size = enclave_size()?;
        let est_sys_overhead = 1024 * 1024 * 256;
        let est_vm_overhead = 1024 * 1024;
        let memory_per_vm = self.instance_memory_size.saturating_add(est_vm_overhead);
        let allowed_instances = enclave_size
            .saturating_sub(est_sys_overhead)
            .saturating_div(memory_per_vm);
        Some(allowed_instances as usize)
    }

    fn validate_mem_size(&self) -> Result<()> {
        let Some(allowed_instances) = self.max_allowed_instances() else {
            warn!("WAPOD_ENCLAVE_SIZE is not set, skipping validation");
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

fn parse_size(input: &str) -> Result<u64, parse_size::Error> {
    parse_size::Config::new().with_binary().parse_size(input)
}

fn enclave_size() -> Option<u64> {
    let Ok(enclave_mem_size) = std::env::var("WAPOD_ENCLAVE_SIZE") else {
        return None;
    };
    let enclave_mem_size: u64 =
        parse_size(&enclave_mem_size).expect("invalid value of WAPOD_ENCLAVE_SIZE");
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

    let key = worker_key::worker_identity_key().public();
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
    let todo = "add prpc get worker description";
    let todo = "guest tip in metrics";

    let todo = "test signing with worker key for guest";
    let todo = "test sgx_quote api for guest";
    let todo = "test preemptive query instance";
    let todo = "tests for query signing";
    let todo = "whether the mr_enclave changes if signer changes?";
    let todo = "limit wasm blob size";
    let todo = "demo for quote/sign verification";
}
