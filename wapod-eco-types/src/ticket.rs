use scale::{Decode, Encode, MaxEncodedLen};
use wapod_crypto_types::{worker_signed_message::verify_message, ContentType, CryptoProvider};

use crate::primitives::{BoundedString, BoundedVec, WorkerPubkey};

pub type String512 = BoundedString<512>;
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
    /// URLs to download the required resources.
    pub download_urls: BoundedVec<String512, 4>,
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

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct WorkerDescription {
    pub prices: Prices,
    pub description: BoundedString<1024>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
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
