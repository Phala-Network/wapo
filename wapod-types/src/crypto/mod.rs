//! Cryptographic primitives and utilities.

use crate::{primitives::BoundedVec, ContentType};

pub mod query;
pub mod verify;

/// A cryptographic signature. Used when talking to the pallet.
pub type Signature = BoundedVec<u8, 128>;

/// A type implementing this trait provides cryptographic primitives.
pub trait CryptoProvider {
    /// Verify a sr25519 signature.
    fn sr25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
    /// Calculate the keccak 256-bit hash of the given data.
    fn keccak_256(data: &[u8]) -> [u8; 32];
    /// Calculate the blake2b 256-bit hash of the given data.
    fn blake2b_256(data: &[u8]) -> [u8; 32];
}
