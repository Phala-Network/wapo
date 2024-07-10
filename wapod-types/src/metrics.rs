use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use alloc::vec::Vec;

use crate::{Address, Bytes32};

#[derive(Decode, Encode, TypeInfo, MaxEncodedLen, Debug, Clone, PartialEq, Eq, Default)]
pub struct MetricsToken {
    pub sn: u64,
    pub session: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Debug, Encode, Decode)]
pub struct AppMetrics {
    pub address: Address,
    pub session: Bytes32,
    pub running_time_ms: u64,
    pub gas_consumed: u64,
    pub network_ingress: u64,
    pub network_egress: u64,
    pub storage_read: u64,
    pub storage_write: u64,
    pub tip: u64,
    pub starts: u64,
}

#[derive(Debug, Encode, Decode)]
pub struct AppsMetrics {
    pub token: MetricsToken,
    pub apps: Vec<AppMetrics>,
}

#[derive(Debug, Encode, Decode)]
pub enum VersionedAppsMetrics {
    V0(AppsMetrics),
}
