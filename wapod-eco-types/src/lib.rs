#![cfg_attr(not(feature = "std"), no_std)]

pub use scale;
pub use wapod_crypto_types as crypto;

pub mod bench_app {
    use scale::{Decode, Encode};

    /// The message that the benchmark app sends emits.
    #[derive(Encode, Decode)]
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
    #[derive(Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedMessage {
        pub message: SigningMessage,
        pub signature: Vec<u8>,
    }
}
