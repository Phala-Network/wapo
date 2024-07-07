use scale::{Decode, Encode};
use scale_info::TypeInfo;

use crate::{Address, Hash, Pubkey};

#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub struct WorkerRegistrationInfoV2 {
    pub version: u32,
    pub machine_id: Vec<u8>,
    pub pubkey: Pubkey,
    pub ecdh_pubkey: Pubkey,
    pub genesis_block_hash: Hash,
    pub features: Vec<u32>,
    pub operator: Option<Address>,
    pub para_id: u32,
    pub max_consensus_version: u32,
}

#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub enum AttestationReport {
    SgxIas,
    SgxDcap {
        quote: Vec<u8>,
        collateral: Option<()>,
    },
}

#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub enum VersionedWorkerEndpoints {
    V1(Vec<String>),
}

#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub struct WorkerEndpointPayload {
    pub pubkey: Pubkey,
    pub versioned_endpoints: VersionedWorkerEndpoints,
    pub signing_time: u64,
}
