pub use rpc_client::WorkerClient;

mod rpc_client;
pub mod register;
pub mod endpoints;
pub mod chain_state;


pub async fn run() {
    // sync chain state
    // hunt for new tickets
    // hunt for heartbeat
    // hunt for new bench apps
    // monitor worker state, schedule jobs
    // submit bench score
}