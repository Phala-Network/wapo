use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use sp_core::hashing::blake2_256;
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use wapod_pherry::{
    bridge::{run_bridge, BridgeConfig},
    deploy,
    endpoints::{update_endpoint, UpdateEndpointArgs},
    register::{register, RegisterArgs},
};
use wapod_types::{
    ticket::{ticket_account_address, TicketId},
    Address,
};

#[derive(Parser, Clone, Debug)]
struct CommonArgs {
    #[arg(long, default_value = "ws://localhost:9944/ws")]
    node_url: String,
    #[arg(long, default_value = "http://localhost:8001")]
    worker_url: String,
    #[arg(long, default_value_t = String::new())]
    token: String,
    #[arg(long, default_value = "//Ferdie")]
    signer: String,
}

#[derive(Parser, Clone, Debug)]
#[clap(version, author)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Clone, Debug)]
enum Command {
    Register {
        #[command(flatten)]
        other: CommonArgs,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        pccs_url: String,
    },
    UpdateEndpoint {
        #[command(flatten)]
        other: CommonArgs,
        #[arg(long)]
        endpoint: String,
    },
    Bridge {
        #[command(flatten)]
        other: CommonArgs,
        /// The operator account.
        #[arg(long)]
        operator: Option<String>,
        /// The PCCS URL.
        #[arg(long, default_value = "")]
        pccs_url: String,
        /// The base URL of the IPFS gateway.
        #[arg(long, default_value = "https://ipfs.io/ipfs/")]
        ipfs_url: String,
        /// The cache directory of IPFS.
        #[arg(long, default_value = "./data/ipfs_cache")]
        ipfs_cache_dir: String,
        /// The maximum number of apps that can be deployed.
        #[arg(long, default_value = "128")]
        max_apps: usize,
        /// The interval in seconds of reporting app metrics.
        #[arg(long, default_value = "600")]
        metrics_interval: u64,
        /// The account to receive rewards.
        #[arg(long)]
        recipient: String,
        /// Waiting for the benchmark app to consume amount of gas until report the init score.
        #[arg(long, default_value = "1000000000")]
        gas_until_report: u64,
        /// Reuse app instance to handle incoming query and TLS connection.
        #[arg(long)]
        reuse_instances: bool,
    },
    CreateWorkerList {
        #[command(flatten)]
        other: CommonArgs,
    },
    Build {
        /// The path to the config file.
        #[arg(long, short, default_value = "WapodDeploy.json")]
        config: String,
    },
    Deploy {
        #[command(flatten)]
        other: CommonArgs,
        /// The path to the config file.
        #[arg(long, short, default_value = "WapodDeploy.json")]
        config: String,
        #[arg(long)]
        worker_list: u64,
        #[arg(long, default_value = "10000000000")]
        deposit: u128,
    },
    TicketAddress {
        ticket_id: TicketId,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();
    match args.command {
        Command::Register {
            operator,
            pccs_url,
            other,
        } => {
            let args = RegisterArgs {
                worker_url: other.worker_url,
                token: other.token,
                node_url: other.node_url,
                signer: other.signer,
                operator,
                pccs_url,
            };
            register(args).await?;
        }
        Command::UpdateEndpoint { endpoint, other } => {
            let args = UpdateEndpointArgs {
                worker_url: other.worker_url,
                token: other.token,
                node_url: other.node_url,
                signer: other.signer,
                endpoint,
            };
            update_endpoint(args).await?;
        }
        Command::Bridge {
            other,
            ipfs_url,
            ipfs_cache_dir,
            max_apps,
            metrics_interval,
            recipient,
            operator,
            pccs_url,
            gas_until_report,
            reuse_instances,
        } => {
            let config = BridgeConfig {
                node_url: other.node_url,
                tx_signer: other.signer,
                worker_url: other.worker_url,
                worker_token: other.token,
                ipfs_base_url: ipfs_url,
                ipfs_cache_dir,
                max_apps,
                metrics_interval: Duration::from_secs(metrics_interval),
                recipient,
                operator: operator.unwrap_or_default(),
                pccs_url,
                gas_until_report,
                reuse_instances,
            };
            run_bridge(config).await?;
        }
        Command::CreateWorkerList { other } => {
            deploy::create_worker_list(other.node_url, other.signer, other.worker_url, other.token)
                .await?;
        }
        Command::Build { config } => {
            deploy::build_manifest(config)?;
        }
        Command::Deploy {
            other,
            config,
            worker_list,
            deposit,
        } => {
            deploy::deploy_manifest(config, &other.node_url, &other.signer, deposit, worker_list)
                .await?;
        }
        Command::TicketAddress { ticket_id } => {
            let address: Address = ticket_account_address(ticket_id, blake2_256);
            println!("0x{}", hex_fmt::HexFmt(address));
        }
    }
    Ok(())
}
