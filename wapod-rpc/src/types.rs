use scale::{Decode, Encode};
use wapod_crypto_types::query::{RootOrCertificate, Signature};

pub type QuerySignature = Signature<RootOrCertificate>;

pub type Address = [u8; 32];
pub type Bytes32 = [u8; 32];

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
    pub session: Bytes32,
    pub nonce: Bytes32,
    pub apps: Vec<AppMetrics>,
}

#[derive(Debug, Encode, Decode)]
pub enum VersionedAppsMetrics {
    V0(AppsMetrics),
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct WorkerRegistrationInfoV2 {
    pub version: u32,
    pub machine_id: Vec<u8>,
    pub pubkey: [u8; 32],
    pub ecdh_pubkey: [u8; 32],
    pub genesis_block_hash: [u8; 32],
    pub features: Vec<u32>,
    pub operator: Option<[u8; 32]>,
    pub para_id: u32,
    pub max_consensus_version: u32,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum AttestationReport {
    SgxIas,
    SgxDcap {
        quote: Vec<u8>,
        collateral: Option<()>,
    },
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum VersionedWorkerEndpoints {
    V1(Vec<String>),
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct WorkerEndpointPayload {
    pub pubkey: [u8; 32],
    pub versioned_endpoints: VersionedWorkerEndpoints,
    pub signing_time: u64,
}
