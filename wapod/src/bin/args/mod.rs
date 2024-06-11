use anyhow::{bail, Context as _, Result};
use clap::Parser;
use tracing::{info, warn};
use typed_builder::TypedBuilder;
use wapod::WorkerArgs;

#[derive(Parser, Clone, Debug, TypedBuilder)]
#[clap(about = "wapod - a WASM runtime", version, author)]
pub struct Args {
    /// Maximum memory size for each instance.
    #[arg(long, short='m', default_value = "128M", value_parser = parse_size)]
    #[builder(default = 128 * 1024 * 1024)]
    pub instance_memory_size: u64,

    /// Maximum number of instances to run. If not specified, it will be determined by the enclave
    /// size and instance memory size.
    #[arg(long, short = 'c', default_value_t = 8)]
    #[builder(default = 8)]
    pub max_instances: usize,

    /// Port number for the admin service to listen on. If not specified, the value will be
    /// read from the configuration file.
    #[arg(long)]
    #[builder(default, setter(strip_option))]
    pub admin_port: Option<u16>,

    /// API token required for accessing the admin service. If empty, no token is required.
    /// When provided, the token must be included in the `Authorization: Bearer` header for
    /// each incoming request.
    #[arg(long, short='t', default_value_t = String::new())]
    #[builder(default)]
    pub admin_api_token: String,

    /// Port number for the user service to listen on. If not specified, the value will be
    /// read from the configuration file.
    #[arg(long)]
    #[builder(default, setter(strip_option))]
    pub user_port: Option<u16>,

    /// Number of compiled WebAssembly modules that can be cached (default: 16).
    #[arg(long, default_value_t = 16)]
    #[builder(default = 16)]
    pub module_cache_size: usize,

    /// Disable memory pool for instances.
    #[arg(long)]
    #[builder(default)]
    pub no_mem_pool: bool,

    /// Tcp port range for the worker to listen on.
    #[arg(long, short = 'l', value_parser = parse_port_range)]
    pub tcp_listen_port_range: Option<(u16, u16)>,
}

fn parse_port_range(input: &str) -> anyhow::Result<(u16, u16)> {
    if input == "none" {
        return Ok((1, 0));
    }
    let mut parts = input.split("..");
    let start = parts
        .next()
        .context("invalid port range")?
        .parse()
        .context("invalid port range")?;
    let end = parts
        .next()
        .context("invalid port range")?
        .parse()
        .context("invalid port range")?;
    if start > end {
        bail!("invalid port range");
    }
    Ok((start, end))
}

impl From<Args> for WorkerArgs {
    fn from(value: Args) -> Self {
        WorkerArgs {
            instance_memory_size: value.instance_memory_size,
            max_instances: value.max_instances,
            module_cache_size: value.module_cache_size,
            no_mem_pool: value.no_mem_pool,
            use_winch: false,
            tcp_listen_port_range: value.tcp_listen_port_range.map_or(1..=0, |(f, t)| f..=t),
        }
    }
}

impl Args {
    pub fn parse() -> Self {
        Parser::parse()
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_mem_size()?;
        Ok(())
    }

    pub(crate) fn max_instances(&self) -> usize {
        self.max_instances
    }

    pub(crate) fn max_allowed_instances(&self) -> Option<usize> {
        let enclave_size = enclave_size()?;
        let est_sys_overhead = 1024 * 1024 * 256;
        let est_vm_overhead = 1024 * 1024;
        let memory_per_vm = self.instance_memory_size.saturating_add(est_vm_overhead);
        let allowed_instances = enclave_size
            .saturating_sub(est_sys_overhead)
            .saturating_div(memory_per_vm);
        Some(allowed_instances as usize)
    }

    pub(crate) fn validate_mem_size(&self) -> Result<()> {
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
            bail!("max_instances is too large");
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
