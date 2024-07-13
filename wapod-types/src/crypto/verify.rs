use alloc::vec::Vec;

use super::{ContentType, CryptoProvider};

pub trait Verifiable {
    fn verify<Crypto: CryptoProvider>(&self) -> bool;
}

pub fn verify_message<Crypto: CryptoProvider>(
    content_type: ContentType,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    let message = content_type.wrap_message(message);
    Crypto::sr25519_verify(public_key, &message, signature)
}

pub fn verify_app_data<Crypto: CryptoProvider>(
    address: &[u8],
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    let message = wrap_app_data(address, message);
    Crypto::sr25519_verify(public_key, &message, signature)
}

pub fn wrap_app_data(address: &[u8], message: &[u8]) -> Vec<u8> {
    ContentType::AppData.wrap_message_iter(address.iter().chain(message.iter()).copied())
}

pub fn sgx_quote_app_data<Crypto: CryptoProvider>(address: &[u8], message: &[u8]) -> [u8; 64] {
    let message = wrap_app_data(address, message);
    let hash = Crypto::keccak_256(&message);
    let mut user_data = hash.to_vec();
    user_data.extend_from_slice([0u8; 32].as_ref());
    user_data.try_into().expect("execpted 64 bytes")
}
