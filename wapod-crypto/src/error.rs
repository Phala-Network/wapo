#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid AEAD key")]
    InvalidAeadKey,
    #[error("Other crypto error")]
    CryptoError,
}
