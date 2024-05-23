use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};
use wapod_pherry::{
    endpoints::{update_endpoint, UpdateEndpointArgs},
    register::{register, RegisterArgs},
};

#[derive(Parser, Clone, Debug)]
#[clap(version, author)]
struct Args {
    #[arg(long)]
    chain_uri: String,
    #[arg(long)]
    worker_uri: String,
    #[arg(long, default_value_t = String::new())]
    token: String,
    #[arg(long, default_value = "//Alice")]
    signer: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Clone, Debug)]
enum Command {
    Register {
        #[arg(
            long,
            default_value = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )]
        operator: String,
        #[arg(long)]
        pccs: String,
    },
    UpdateEndpoint {
        #[arg(long)]
        endpoint: String,
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
        Command::Register { operator, pccs } => {
            let args = RegisterArgs {
                worker_uri: args.worker_uri,
                token: args.token,
                chain_uri: args.chain_uri,
                signer: args.signer,
                operator,
                pccs_url: pccs,
            };
            register(args).await?;
        }
        Command::UpdateEndpoint { endpoint } => {
            let args = UpdateEndpointArgs {
                worker_uri: args.worker_uri,
                token: args.token,
                chain_uri: args.chain_uri,
                endpoint,
                signer: args.signer,
            };
            update_endpoint(args).await?;
        }
    }
    Ok(())
}
