#![cfg_attr(not(test), no_main)]

mod bench;
mod query;

#[wapo::main]
async fn main() {
    wapo::logger::init();
    tokio::select! {
        _ = bench::benchmark() => {}
        _ = query::query_serve() => {}
    }
}
