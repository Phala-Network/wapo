use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use wapod_pherry::{
    chain_state::monitor_chain_state,
    endpoints::{update_endpoint, UpdateEndpointArgs},
    register::{register, RegisterArgs},
};

#[derive(Parser, Clone, Debug)]
struct CommonArgs {
    #[arg(long)]
    chain_uri: String,
    #[arg(long, default_value = "http://localhost:8001")]
    worker_uri: String,
    #[arg(long, default_value_t = String::new())]
    token: String,
    #[arg(long, default_value = "//Alice")]
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
        #[arg(
            long,
            default_value = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )]
        operator: String,
        #[arg(long)]
        pccs: String,
    },
    Update {
        #[command(flatten)]
        other: CommonArgs,
        #[arg(long)]
        endpoint: String,
    },
    Test {
        #[command(flatten)]
        other: CommonArgs,
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
            pccs,
            other,
        } => {
            let args = RegisterArgs {
                worker_uri: other.worker_uri,
                token: other.token,
                chain_uri: other.chain_uri,
                signer: other.signer,
                operator,
                pccs_url: pccs,
            };
            register(args).await?;
        }
        Command::Update { endpoint, other } => {
            let args = UpdateEndpointArgs {
                worker_uri: other.worker_uri,
                token: other.token,
                chain_uri: other.chain_uri,
                signer: other.signer,
                endpoint,
            };
            update_endpoint(args).await?;
        }
        Command::Test { other } => {
            // let mut rx = monitor_chain_state(uri);
            // while let Some(state) = rx.recv().await {
            //     println!("state received: num tickets={}", state.tickets.len());
            // }
        }
    }
    Ok(())
}
