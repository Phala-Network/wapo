use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        verify::{verify_message, Verifiable},
        CryptoProvider, Signature,
    },
    primitives::{BoundedVec, WorkerPubkey},
    ticket::TicketId,
    Address, Bytes32, ContentType,
};

#[derive(
    Decode,
    Encode,
    TypeInfo,
    MaxEncodedLen,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
)]
pub struct MetricsToken {
    pub sn: u64,
    pub session: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Debug, Encode, Decode, TypeInfo, MaxEncodedLen, Clone, PartialEq, Eq)]
pub struct AppMetrics {
    pub address: Address,
    pub session: Bytes32,
    pub running_time_ms: u64,
    pub gas_consumed: u64,
    pub network_ingress: u64,
    pub network_egress: u64,
    pub storage_read: u64,
    pub storage_write: u64,
    pub storage_used: u128,
    pub memory_used: u128,
    pub tip: u64,
    pub starts: u64,
}

pub const MAX_APPS_METRICS: usize = 64;
pub const MAX_CLAIM_TICKETS: usize = 3;

#[derive(Debug, Encode, Decode, TypeInfo, MaxEncodedLen, Clone, PartialEq, Eq)]
pub struct AppsMetrics {
    pub token: MetricsToken,
    pub apps: BoundedVec<AppMetrics, MAX_APPS_METRICS>,
}

#[derive(Debug, Encode, Decode, TypeInfo, MaxEncodedLen, Clone, PartialEq, Eq)]
pub enum VersionedAppsMetrics {
    V0(AppsMetrics),
}

pub type ClaimMap =
    BoundedVec<(Address, BoundedVec<TicketId, MAX_CLAIM_TICKETS>), MAX_APPS_METRICS>;

#[derive(Debug, Encode, Decode, TypeInfo, MaxEncodedLen, Clone, PartialEq, Eq)]
pub struct SignedAppsMetrics {
    pub metrics: VersionedAppsMetrics,
    pub signature: Signature,
    pub worker_pubkey: WorkerPubkey,
    // A map of app addresses to the tickets that the worker wants to claim.
    pub claim_map: ClaimMap,
}

impl SignedAppsMetrics {
    pub fn new(
        metrics: VersionedAppsMetrics,
        signature: BoundedVec<u8, 128>,
        worker_pubkey: WorkerPubkey,
        claim_map: ClaimMap,
    ) -> Self {
        Self {
            metrics,
            signature,
            worker_pubkey,
            claim_map,
        }
    }
}
impl Verifiable for SignedAppsMetrics {
    fn verify<Crypto: CryptoProvider>(&self) -> bool {
        let encoded_message = self.metrics.encode();
        verify_message::<Crypto>(
            ContentType::Metrics,
            &encoded_message,
            &self.signature,
            &self.worker_pubkey,
        )
    }
}
