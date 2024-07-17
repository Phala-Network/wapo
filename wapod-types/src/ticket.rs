//! Types related to the ticket system.

use alloc::string::String;
use alloc::vec::Vec;

use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        verify::{verify_message, Verifiable},
        CryptoProvider, Signature,
    },
    helpers::scale::TrailingZeroInput,
    metrics::AppMetrics,
    primitives::{BoundedString, WorkerPubkey},
    ContentType,
};

/// The ticket id type.
pub type TicketId = u64;
/// The balance type.
pub type Balance = u128;

/// The manifest of an application.
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
    /// Calculate the address of the application.
    pub fn address(&self, blake2_256_fn: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
        blake2_256_fn(&self.encode())
    }
}

/// Resource prices.
#[derive(Encode, Decode, TypeInfo, Default, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
pub struct Prices {
    /// The general fee per second.
    pub general_fee_per_second: Option<Balance>,
    /// The gas price. (balance per gas)
    pub gas_price: Option<Balance>,
    /// The network ingress price. (balance per byte)
    pub net_ingress_price: Option<Balance>,
    /// The network egress price. (balance per byte)
    pub net_egress_price: Option<Balance>,
    /// The storage read price. (balance per byte)
    pub storage_read_price: Option<Balance>,
    /// The storage write price. (balance per byte)
    pub storage_write_price: Option<Balance>,
    /// The storage price. (balance per MB*second)
    pub storage_price: Option<Balance>,
    /// The memory price. (balance per KB*second)
    pub memory_price: Option<Balance>,
    /// The tip price. (balance per tip)
    pub tip_price: Option<Balance>,
}

impl Prices {
    /// Check if the prices are empty.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Calculate the cost of the given metrics.
    pub fn cost_of(&self, rhs: &AppMetrics) -> Balance {
        let mut total: Balance = 0;
        macro_rules! add_mul {
            ($price: expr, $usage: expr) => {
                if let Some(price) = $price {
                    let cost = price.saturating_mul($usage as Balance);
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

    /// Merge two prices together. If a field is present in both, the one in `self` will be used.
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

/// A worker description.
#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
pub struct WorkerDescription {
    /// The resource prices of the worker.
    pub prices: Prices,
    /// The description text of the worker.
    pub description: BoundedString<1024>,
}

/// A signed worker description.
#[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq, MaxEncodedLen)]
pub struct SignedWorkerDescription {
    /// The description content.
    pub worker_description: WorkerDescription,
    /// The signature of the description.
    pub signature: Signature,
    /// The public key of the worker.
    pub worker_pubkey: WorkerPubkey,
}

impl Verifiable for SignedWorkerDescription {
    fn verify<Crypto: CryptoProvider>(&self) -> bool {
        let encoded_message = self.worker_description.encode();
        verify_message::<Crypto>(
            ContentType::WorkerDescription,
            &encoded_message,
            &self.signature,
            &self.worker_pubkey,
        )
    }
}

/// Calculate the deposit account id of a ticket.
pub fn ticket_account_address<T>(ticket_id: TicketId, blake2_256_fn: fn(&[u8]) -> [u8; 32]) -> T
where
    T: Encode + Decode,
{
    let hash = blake2_256_fn(&(b"wapod/ticket/", ticket_id).encode());
    T::decode(&mut TrailingZeroInput::new(&hash))
        .expect("Decoding zero-padded account id should always succeed; qed")
}
