use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::{
    crypto::{verify::verify_app_data, CryptoProvider},
    primitives::{Address, BoundedVec, WorkerPubkey},
};

#[derive(Decode, Encode, TypeInfo, MaxEncodedLen, Debug, Clone, PartialEq, Eq, Default)]
pub struct MetricsToken {
    pub worker_session: [u8; 32],
    pub nonce: [u8; 32],
    pub metrics_sn: u64,
}

/// The message that the benchmark app sends emits.
#[derive(Decode, Encode, TypeInfo, MaxEncodedLen, Debug, Clone, PartialEq, Eq)]
pub enum SigningMessage {
    /// A benchmark score. This can be submitted to the chain as the worker's initial score.
    BenchScore {
        /// The score.
        gas_per_second: u64,
        /// The amount of gas consumed to calculate the score.
        gas_consumed: u64,
        /// The timestamp (seconds since UNIX epoch) when the score was recorded.
        timestamp_secs: u64,
        /// The metrics token for the worker.
        matrics_token: MetricsToken,
    },
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
