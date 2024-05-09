#![no_main]

use std::time::Duration;

use wapo::time::sleep;

#[wapo::main]
async fn main() {
    loop {
        println!("Hello, world!");
        sleep(Duration::from_secs(1)).await;
    }
}
