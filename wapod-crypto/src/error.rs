#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid AEAD key")]
    InvalidAeadKey,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Other crypto error")]
    CryptoError,
}
