#![cfg_attr(not(test), no_main)]

use std::time::Duration;

#[wapo::main]
async fn main() {
    wapo::logger::init();

    benchmark().await;
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

async fn benchmark() {
    let mut init = sha256(b"init");
    let start = std::time::Instant::now();
    for epoch in 0.. {
        for _ in 0..100000 {
            init = sha256(&init);
        }
        let gas = wapo::ocall::app_gas_consumed().unwrap();
        let dt = start.elapsed();
        let gas_per_sec = gas as f64 / dt.as_secs_f64();
        let time_to_overflow = (u64::MAX - gas) as f64 / gas_per_sec / 3600f64 / 24f64 / 365.25;
        let rm = log::info!("epoch: {epoch}, gas: {gas}");
        log::info!("gas per sec: {gas_per_sec}");
        log::info!("time to overflow: {time_to_overflow} years");
        wapo::time::sleep(Duration::from_millis(1)).await;
    }
}
