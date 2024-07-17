//! The query module provides types for the wapod query RPC request and response.

use alloc::{string::String, vec::Vec};
use scale::{Decode, Encode};

/// The query signature type.
pub type QuerySignature = Signature<RootOrCertificate>;

/// A query request.
#[derive(Clone, Encode, Decode)]
pub struct Query {
    /// The dest app address of the query.
    pub address: Vec<u8>,
    /// The path of the query.
    pub path: String,
    /// The query payload.
    pub payload: Vec<u8>,
}


/// A signature signed by a worker for query response.
#[derive(Encode, Decode, Clone)]
pub struct Signature<S> {
    /// The signature type
    pub signature_type: SignatureType,
    /// The signature of the data
    pub signature: Vec<u8>,
    /// The certificate of the signer
    pub signer: S,
}

/// The signature type
#[derive(Encode, Decode, Clone, Copy)]
pub enum SignatureType {
    /// A substrate-flavor ed25519 signature.
    Ed25519 = 0,
    /// A substrate-flavor sr25519 signature.
    Sr25519 = 1,
    /// A substrate-flavor ecdsa signature.
    Ecdsa = 2,
    /// A polkadot-wallet signed ed25519 signature.
    Ed25519WrapBytes = 3,
    /// A polkadot-wallet signed sr25519 signature.
    Sr25519WrapBytes = 4,
    /// A polkadot-wallet signed ecdsa signature.
    EcdsaWrapBytes = 5,
    /// An EIP712 signature.
    Eip712 = 6,
    /// An EVM-flavor ECDSA signature.
    EvmEcdsa = 7,
    /// An EVM-flavor ECDSA signature with wrapped bytes.
    EvmEcdsaWrapBytes = 8,
}

/// A root signer.
#[derive(Clone, Encode, Decode)]
pub struct RootSigner {
    /// The public key of the root signer.
    pub pubkey: Vec<u8>,
}

/// A root signer or a signed certificate.
#[derive(Clone, Encode, Decode)]
pub enum RootOrCertificate {
    /// A root signer.
    Root(RootSigner),
    /// A signed certificate.
    Certificate(Certificate),
}

/// A certificate.
#[derive(Encode, Decode, Clone)]
pub struct Certificate {
    /// The body of the certificate
    pub body: CertificateBody,
    /// An optinal signature of the body signed by a parent certificate.
    pub signature: Signature<RootSigner>,
}

/// The body of a certificate.
#[derive(Clone, Encode, Decode, Debug)]
pub struct CertificateBody {
    /// The public key of the certificate.
    pub pubkey: Vec<u8>,
    /// The expiration time of the certificate in seconds since the Unix epoch.
    pub expiration: u64,
    /// The operation scopes that allow the certificate to sign.
    pub scopes: Vec<Scope>,
}

/// The operation scope of a certificate.
#[derive(Clone, Encode, Decode, Debug)]
pub struct Scope {
    /// The application address of the operation.
    pub app: Vec<u8>,
    /// The resources paths that the application.
    pub resources: Vec<String>,
}
