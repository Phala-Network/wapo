use scale::{Decode, Encode, MaxEncodedLen};

use crate::primitives::{BoundedString, BoundedVec};

pub type String256 = BoundedString<256>;
pub type String32 = BoundedString<32>;
pub type Hash = BoundedVec<u8, 64>;

#[derive(Decode, Encode, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct Manifest {
    // The spec version of the manifest.
    pub version: u8,
    // The hash of the app's code.
    pub code: BlobDescription,
    // The arguments of the app.
    pub args: BoundedVec<String256, 32>,
    // The environment variables of the app.
    pub env_vars: BoundedVec<(String256, String256), 32>,
    // The start mode of the app.
    pub on_demand: bool,
    // Whether the app can run multiple instances in a single worker.
    pub resizable: bool,
    // The maximum size of the query payload.
    pub max_query_size: u32,
    // The optional label of the app.
    pub label: String32,
}

impl Manifest {
    pub fn address(&self, blake2_256_fn: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
        blake2_256_fn(&self.encode())
    }
}

/// A ticket.
#[derive(Encode, Decode, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct TicketDescription {
    /// The manifest.
    pub manifest: Manifest,
    /// The blobs that the app required to run.
    pub required_blobs: BoundedVec<BlobDescription, 32>,
    /// Download url
    pub download_url: Option<String256>,
    /// The prices to be paid to workers for running the app.
    pub prices: Prices,
}

#[derive(Encode, Decode, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct BlobDescription {
    /// The hash of the blob.
    pub hash: Hash,
    /// The hash algorithm of the blob.
    pub hash_algorithm: String32,
}

#[derive(Encode, Decode, Default, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct Prices {
    pub general_fee_per_second: Option<u128>,
    pub gas_price: Option<u128>,
    pub net_ingress_price: Option<u128>,
    pub net_egress_price: Option<u128>,
    pub storage_read_price: Option<u128>,
    pub storage_write_price: Option<u128>,
    pub tip_price: Option<u128>,
}
