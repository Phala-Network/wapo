use scale::{Decode, Encode};

pub type Address = [u8; 32];
pub type Bytes32 = [u8; 32];

#[derive(Debug, Encode, Decode)]
pub struct InstanceMetrics {
    pub address: Address,
    pub session: Bytes32,
    pub running_time_ms: u64,
    pub gas_consumed: u64,
    pub network_ingress: u64,
    pub network_egress: u64,
    pub storage_read: u64,
    pub storage_write: u64,
    pub starts: u64,
}

#[derive(Debug, Encode, Decode)]
pub struct Metrics {
    pub session: Bytes32,
    pub nonce: Bytes32,
    pub instances: Vec<InstanceMetrics>,
}
