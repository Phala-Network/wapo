use alloc::{string::String, vec::Vec};
use scale::{Decode, Encode};

pub type QuerySignature = Signature<RootOrCertificate>;

#[derive(Clone, Encode, Decode)]
pub struct Query {
    pub address: Vec<u8>,
    pub path: String,
    pub payload: Vec<u8>,
}

#[derive(Encode, Decode, Clone)]
pub struct Signature<S> {
    /// The signature type
    pub signature_type: SignatureType,
    /// The signature of the data
    pub signature: Vec<u8>,
    /// The certificate of the signer
    pub signer: S,
}

#[derive(Encode, Decode, Clone, Copy)]
pub enum SignatureType {
    Ed25519 = 0,
    Sr25519 = 1,
    Ecdsa = 2,
    Ed25519WrapBytes = 3,
    Sr25519WrapBytes = 4,
    EcdsaWrapBytes = 5,
    Eip712 = 6,
    EvmEcdsa = 7,
    EvmEcdsaWrapBytes = 8,
}

#[derive(Clone, Encode, Decode)]
pub struct RootSigner {
    pub pubkey: Vec<u8>,
}

#[derive(Clone, Encode, Decode)]
pub enum RootOrCertificate {
    Root(RootSigner),
    Certificate(Certificate),
}

#[derive(Encode, Decode, Clone)]
pub struct Certificate {
    /// The body of the certificate
    pub body: CertificateBody,
    /// An optinal signature of the body signed by a parent certificate.
    pub signature: Signature<RootSigner>,
}

#[derive(Clone, Encode, Decode, Debug)]
pub struct CertificateBody {
    /// The public key of the certificate.
    pub pubkey: Vec<u8>,
    /// The expiration time of the certificate in seconds since the Unix epoch.
    pub expiration: u64,
    /// The operation scopes that allow the certificate to sign.
    pub scopes: Vec<Scope>,
}

#[derive(Clone, Encode, Decode, Debug)]
pub struct Scope {
    /// The application address of the operation.
    pub app: Vec<u8>,
    /// The resources paths that the application.
    pub resources: Vec<String>,
}
