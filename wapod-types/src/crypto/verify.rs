//! Verification functions for messages and app data.

use alloc::vec::Vec;

use super::{ContentType, CryptoProvider};

/// A trait for verifying a message.
pub trait Verifiable {
    /// Verify self.
    fn verify<Crypto: CryptoProvider>(&self) -> bool;
}

/// Verify a message with a given content type.
pub fn verify_message<Crypto: CryptoProvider>(
    content_type: ContentType,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    let message = content_type.wrap_message(message);
    Crypto::sr25519_verify(public_key, &message, signature)
}

/// Verify an app data message.
pub fn verify_app_data<Crypto: CryptoProvider>(
    address: &[u8],
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    let message = wrap_app_data(address, message);
    Crypto::sr25519_verify(public_key, &message, signature)
}

/// Wrap an app data message with the app data content type.
///
/// When an app uses `wapo::ocalls::worker_sign`, the underlying worker sign API will
/// receive the same message as calculated by this function.
pub fn wrap_app_data(address: &[u8], message: &[u8]) -> Vec<u8> {
    ContentType::AppData.wrap_message_iter(address.iter().chain(message.iter()).copied())
}

/// Calculate the user data passed to sgx quote for a given app data.
///
/// When an app uses `wapo::ocalls::sgx_quote`, the underlying sgx quote API will
/// receive the same user data as calculated by this function.
pub fn sgx_quote_app_data<Crypto: CryptoProvider>(address: &[u8], message: &[u8]) -> [u8; 64] {
    let message = wrap_app_data(address, message);
    let hash = Crypto::keccak_256(&message);
    let mut user_data = hash.to_vec();
    user_data.extend_from_slice([0u8; 32].as_ref());
    user_data.try_into().expect("execpted 64 bytes")
}
