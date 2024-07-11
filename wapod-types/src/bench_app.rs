use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{verify::verify_app_data, CryptoProvider},
    metrics::MetricsToken,
    primitives::{Address, BoundedVec, WorkerPubkey},
};

/// The json response of the benchmark app.

#[derive(
    Default,
    Debug,
    Serialize,
    Deserialize,
    Decode,
    Encode,
    TypeInfo,
    MaxEncodedLen,
    Clone,
    PartialEq,
    Eq,
)]
pub struct BenchScore {
    /// The score.
    pub gas_per_second: u64,
    /// The amount of gas consumed to calculate the score.
    pub gas_consumed: u64,
    /// The timestamp (seconds since UNIX epoch) when the score was recorded.
    pub timestamp_secs: u64,
    /// The metrics token for the worker.
    pub metrics_token: MetricsToken,
}

/// The message that the benchmark app sends emits.
#[derive(Decode, Encode, TypeInfo, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
pub enum SigningMessage {
    /// A benchmark score. This can be submitted to the chain as the worker's initial score.
    BenchScore(BenchScore),
}

/// A signed message.
#[derive(Decode, Encode, TypeInfo, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    pub message: SigningMessage,
    pub signature: BoundedVec<u8, 128>,
    pub worker_pubkey: WorkerPubkey,
    pub app_address: Address,
}

impl SignedMessage {
    pub fn verify<Crypto: CryptoProvider>(&self) -> bool {
        let encoded_message = self.message.encode();
        verify_app_data::<Crypto>(
            &self.app_address,
            &encoded_message,
            &self.signature,
            &self.worker_pubkey,
        )
    }
}
