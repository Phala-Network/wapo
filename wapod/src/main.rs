use clap::Parser;

mod web_api;

#[derive(Parser)]
#[clap(about = "wapo - a WASM runtime", version, author)]
pub struct Args {
    #[arg(long, default_value_t = 1)]
    workers: usize,
    /// The WASM program to run
    program: Option<String>,
    /// Max memory pages
    #[arg(long, default_value_t = 256)]
    max_memory_pages: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    if std::env::var("ROCKET_PORT").is_err() {
        std::env::set_var("ROCKET_PORT", "8003");
    }
    web_api::serve(Args::parse()).await.unwrap();
    Ok(())
}
