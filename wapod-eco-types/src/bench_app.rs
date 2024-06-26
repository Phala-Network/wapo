use scale::{Decode, Encode, MaxEncodedLen};
use wapod_crypto_types::{worker_signed_message::verify_app_data, CryptoProvider};

use crate::primitives::{Address, BoundedVec, WorkerPubkey};

/// The message that the benchmark app sends emits.
#[derive(Decode, Encode, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum SigningMessage {
    /// A benchmark score. This can be submitted to the chain as the worker's initial score.
    BenchScore {
        /// The score.
        gas_per_second: u64,
        /// The amount of gas consumed to calculate the score.
        gas_consumed: u64,
        /// The timestamp (seconds since UNIX epoch) when the score was recorded.
        timestamp_secs: u64,
    },
}

/// A signed message.
#[derive(Decode, Encode, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
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
