use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::{
    crypto::{verify::verify_message, CryptoProvider},
    primitives::{BoundedString, BoundedVec, WorkerPubkey},
    ContentType,
};

pub type Hash = Vec<u8>;

#[derive(Decode, Encode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    // The spec version of the manifest.
    pub version: u8,
    // The hash of the app's code.
    pub code_hash: String,
    // The arguments of the app.
    pub args: Vec<String>,
    // The environment variables of the app.
    pub env_vars: Vec<(String, String)>,
    // The start mode of the app.
    pub on_demand: bool,
    // Whether the app can run multiple instances in a single worker.
    pub resizable: bool,
    // The maximum size of the query payload.
    pub max_query_size: u32,
    // The optional label of the app.
    pub label: String,
}

impl Manifest {
    pub fn address(&self, blake2_256_fn: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
        blake2_256_fn(&self.encode())
    }
}

/// A ticket.
#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
pub struct TicketDescription {
    /// The manifest.
    pub manifest: Manifest,
    /// The blobs that the app required to run.
    pub required_blobs: BTreeMap<Hash, String>,
}

#[derive(Encode, Decode, TypeInfo, Default, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
pub struct Prices {
    pub general_fee_per_second: Option<u128>,
    pub gas_price: Option<u128>,
    pub net_ingress_price: Option<u128>,
    pub net_egress_price: Option<u128>,
    pub storage_read_price: Option<u128>,
    pub storage_write_price: Option<u128>,
    pub tip_price: Option<u128>,
}

#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
pub struct WorkerDescription {
    pub prices: Prices,
    pub description: BoundedString<1024>,
}

#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
pub struct SignedWorkerDescription {
    pub worker_description: WorkerDescription,
    pub signature: BoundedVec<u8, 128>,
    pub worker_pubkey: WorkerPubkey,
}

impl SignedWorkerDescription {
    pub fn verify<Crypto: CryptoProvider>(&self) -> bool {
        let encoded_message = self.worker_description.encode();
        verify_message::<Crypto>(
            ContentType::WorkerDescription,
            &encoded_message,
            &self.signature,
            &self.worker_pubkey,
        )
    }
}
