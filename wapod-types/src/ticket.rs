use alloc::string::String;
use alloc::vec::Vec;

use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{verify::verify_message, CryptoProvider},
    metrics::AppMetrics,
    primitives::{BoundedString, BoundedVec, WorkerPubkey},
    ContentType,
};

pub type TicketId = u64;

#[derive(Decode, Encode, TypeInfo, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppManifest {
    /// The spec version of the manifest.
    pub version: u32,
    /// The hash of the app's code.
    /// Example: "sha256:1234567812345678123456781234567812345678123456781234567812345678"
    pub code_hash: String,
    /// The arguments of the app.
    pub args: Vec<String>,
    /// The environment variables of the app.
    pub env_vars: Vec<(String, String)>,
    /// The start mode of the app.
    pub on_demand: bool,
    /// Whether the app can run multiple instances in a single worker.
    pub resizable: bool,
    /// The maximum size of the query payload.
    pub max_query_size: u32,
    /// The optional label of the app.
    pub label: String,
    /// The blobs that the app required to run.
    ///
    /// Pair of (hash, cid).
    pub required_blobs: Vec<(String, String)>,
}

impl AppManifest {
    pub fn address(&self, blake2_256_fn: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
        blake2_256_fn(&self.encode())
    }
}

#[derive(Encode, Decode, TypeInfo, Default, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
pub struct Prices {
    pub general_fee_per_second: Option<u128>,
    pub gas_price: Option<u128>,
    pub net_ingress_price: Option<u128>,
    pub net_egress_price: Option<u128>,
    pub storage_read_price: Option<u128>,
    pub storage_write_price: Option<u128>,
    pub storage_price: Option<u128>,
    pub memory_price: Option<u128>,
    pub tip_price: Option<u128>,
}

impl Prices {
    pub fn cost_of(&self, rhs: &AppMetrics) -> u128 {
        let mut total = 0_u128;
        macro_rules! add_mul {
            ($price: expr, $usage: expr) => {
                if let Some(price) = $price {
                    let cost = price.saturating_mul($usage as u128);
                    total = total.saturating_add(cost);
                }
            };
        }
        let running_time = rhs.running_time_ms / 1000;
        add_mul!(self.general_fee_per_second, running_time);
        add_mul!(self.gas_price, rhs.gas_consumed);
        add_mul!(self.net_ingress_price, rhs.network_ingress);
        add_mul!(self.net_egress_price, rhs.network_egress);
        add_mul!(self.storage_read_price, rhs.storage_read);
        add_mul!(self.storage_write_price, rhs.storage_write);
        add_mul!(self.storage_price, rhs.storage_used);
        add_mul!(self.memory_price, rhs.memory_used);
        add_mul!(self.tip_price, rhs.tip);
        total
    }

    pub fn merge(self, other: &Self) -> Self {
        Self {
            general_fee_per_second: self.general_fee_per_second.or(other.general_fee_per_second),
            gas_price: self.gas_price.or(other.gas_price),
            net_ingress_price: self.net_ingress_price.or(other.net_ingress_price),
            net_egress_price: self.net_egress_price.or(other.net_egress_price),
            storage_read_price: self.storage_read_price.or(other.storage_read_price),
            storage_write_price: self.storage_write_price.or(other.storage_write_price),
            storage_price: self.storage_price.or(other.storage_price),
            memory_price: self.memory_price.or(other.memory_price),
            tip_price: self.tip_price.or(other.tip_price),
        }
    }
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
