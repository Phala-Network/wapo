#![cfg_attr(not(test), no_main)]

mod bench;
mod query;

#[wapo::main]
async fn main() {
    wapo::logger::init();
    let filter_str = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    log::info!("benchmark app started, log filter: {filter_str}");
    tokio::select! {
        _ = bench::benchmark() => {}
        _ = query::query_serve() => {}
    }
}
