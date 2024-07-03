use crate::ContentType;

pub mod query;
pub mod verify;

pub trait CryptoProvider {
    fn sr25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
    fn keccak_256(data: &[u8]) -> [u8; 32];
    fn blake2b_256(data: &[u8]) -> [u8; 32];
}
