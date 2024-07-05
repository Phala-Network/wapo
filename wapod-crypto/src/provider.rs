use super::CryptoProvider;

pub struct SpCoreHash;

impl CryptoProvider for SpCoreHash {
    fn sr25519_verify(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
        false
    }

    fn keccak_256(data: &[u8]) -> [u8; 32] {
        sp_core::keccak_256(data)
    }

    fn blake2b_256(data: &[u8]) -> [u8; 32] {
        sp_core::blake2_256(data)
    }
}
