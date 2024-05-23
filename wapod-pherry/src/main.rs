use anyhow::Result;
use clap::{Parser, Subcommand};
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
        #[arg(long, default_value = "//Alice")]
        operator: String,
        pccs: String,
    },
    UpdateEndpoint {
        #[arg(long)]
        endpoint: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

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
