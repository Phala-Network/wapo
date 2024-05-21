use scale::{Decode, Encode, Error as CodecError};
use sp_core::{H160, H256};
use std::convert::TryFrom;

mod eip712;

type AccountId = [u8; 32];
type Result<T, E = SignatureVerifyError> = core::result::Result<T, E>;

#[derive(Clone, Encode, Decode)]
pub struct Query {
    address: Vec<u8>,
    path: String,
    payload: Vec<u8>,
}

pub trait Signer {
    fn verify_query(
        &self,
        query: &Query,
        signature: &[u8],
        sig_type: SignatureType,
    ) -> Result<AccountId>;
}

#[derive(Clone, Encode, Decode)]
pub struct RootSigner {
    pubkey: Vec<u8>,
}

#[derive(Clone, Encode, Decode)]
pub enum RootOrCertificate {
    Root(RootSigner),
    Certificate(Certificate),
}

impl RootSigner {
    fn verify_cert(
        &self,
        cert: &Certificate,
        signature: &[u8],
        sig_type: SignatureType,
    ) -> Result<AccountId> {
        match sig_type {
            SignatureType::Eip712 => eip712_verify_cert(&self.pubkey, cert, signature),
            _ => non_eip712_verify(&self.pubkey, &cert.encode(), signature, sig_type, 0),
        }
    }
}

impl Signer for RootSigner {
    fn verify_query(
        &self,
        query: &Query,
        signature: &[u8],
        sig_type: SignatureType,
    ) -> Result<AccountId> {
        match sig_type {
            SignatureType::Eip712 => {
                eip712_verify_query(&self.pubkey, query.clone(), signature, false)
            }
            _ => non_eip712_verify(&self.pubkey, &query.encode(), signature, sig_type, 1),
        }
    }
}

impl Signer for Certificate {
    fn verify_query(
        &self,
        query: &Query,
        signature: &[u8],
        sig_type: SignatureType,
    ) -> Result<AccountId, SignatureVerifyError> {
        let todo = "owned query";
        match sig_type {
            SignatureType::Eip712 => {
                eip712_verify_query(&self.body.pubkey, query.clone(), signature, true)
            }
            _ => non_eip712_verify(&self.body.pubkey, &query.encode(), signature, sig_type, 2),
        }
    }
}

impl Signer for RootOrCertificate {
    fn verify_query(
        &self,
        query: &Query,
        signature: &[u8],
        sig_type: SignatureType,
    ) -> Result<AccountId> {
        match self {
            RootOrCertificate::Root(root) => root.verify_query(query, signature, sig_type),
            RootOrCertificate::Certificate(cert) => cert.verify_query(query, signature, sig_type),
        }
    }
}

#[derive(Encode, Decode, Clone)]
pub struct Signature<S: Signer> {
    /// The signature type
    pub signature_type: SignatureType,
    /// The signature of the data
    pub signature: Vec<u8>,
    /// The certificate of the signer
    pub signer: S,
}

#[derive(Encode, Decode, Clone)]
pub struct Certificate {
    /// The body of the certificate
    pub body: CertificateBody,
    /// An optinal signature of the body signed by a parent certificate.
    pub signature: Signature<RootSigner>,
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

#[derive(Clone, Encode, Decode, Debug)]
pub struct CertificateBody {
    pub pubkey: Vec<u8>,
    pub expiration: u64,
    pub scopes: Vec<Scope>,
}

#[derive(Clone, Encode, Decode, Debug)]
pub struct Scope {
    pub app: Vec<u8>,
    pub resources: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum SignatureVerifyError {
    InvalidSignatureType,
    InvalidSignature,
    CertificateMissing,
    CertificateExpired,
    TooLongCertificateChain,
    DecodeFailed(CodecError),
    InvalidPublicKey,
    Eip712EncodingError,
}

impl From<CodecError> for SignatureVerifyError {
    fn from(err: CodecError) -> Self {
        SignatureVerifyError::DecodeFailed(err)
    }
}

pub fn verify<T>(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> bool
where
    T: sp_core::crypto::Pair,
    T::Public: for<'a> TryFrom<&'a [u8]>,
    T::Signature: for<'a> TryFrom<&'a [u8]>,
{
    let Ok(public) = T::Public::try_from(pubkey) else {
        return false;
    };
    let Ok(signature) = T::Signature::try_from(sig) else {
        return false;
    };
    T::verify(&signature, msg, &public)
}

/// Verify the Substrate signatures and return the public key
fn sub_recover<T>(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<T::Public, SignatureVerifyError>
where
    T: sp_core::crypto::Pair,
    T::Public: for<'a> TryFrom<&'a [u8]>,
    T::Signature: for<'a> TryFrom<&'a [u8]>,
{
    let Ok(public) = T::Public::try_from(pubkey) else {
        return Err(SignatureVerifyError::InvalidPublicKey);
    };
    verify::<T>(pubkey, sig, msg)
        .then_some(public)
        .ok_or(SignatureVerifyError::InvalidSignature)
}

/// Wraps the message in the same format as it defined in Polkadot.js extension:
///   https://github.com/polkadot-js/extension/blob/e4ce268b1cad5e39e75a2195e3aa6d0344de7745/packages/extension-dapp/src/wrapBytes.ts
fn wrap_bytes(msg: &[u8]) -> Vec<u8> {
    let mut wrapped = Vec::<u8>::new();
    wrapped.extend_from_slice(b"<Bytes>");
    wrapped.extend_from_slice(msg);
    wrapped.extend_from_slice(b"</Bytes>");
    wrapped
}

fn evm_ecdsa_recover(
    mut signature: [u8; 65],
    message_hash: [u8; 32],
) -> Result<sp_core::ecdsa::Public, SignatureVerifyError> {
    if signature[64] >= 27 {
        signature[64] -= 27;
    }
    let signature = sp_core::ecdsa::Signature::from_raw(signature);
    let recovered_pubkey = signature
        .recover_prehashed(&message_hash)
        .ok_or(SignatureVerifyError::InvalidSignature)?;
    Ok(recovered_pubkey)
}

/// Convert EVM public key to Substrate account ID.
///
/// account_id = keccak256(pubkey)[12..] + b"@evm_address"
fn account_id_from_evm_pubkey(pubkey: sp_core::ecdsa::Public) -> Result<AccountId> {
    let h20 = evm_pubkey_to_adderss(pubkey.as_ref())?;
    let mut raw_account: [u8; 32] = [0; 32];
    let postfix = b"@evm_address";
    raw_account[..20].copy_from_slice(h20.as_bytes());
    raw_account[20..].copy_from_slice(postfix);
    Ok(AccountId::from(raw_account))
}

fn evm_pubkey_to_adderss(pubkey: &[u8]) -> Result<H160> {
    let pubkey = secp256k1::PublicKey::from_slice(pubkey)
        .map_err(|_| SignatureVerifyError::InvalidPublicKey)?;
    let h32 = H256(sp_core::hashing::keccak_256(
        &pubkey.serialize_uncompressed()[1..],
    ));
    Ok(h32.into())
}

#[test]
fn test_account_id_from_evm_pubkey() {
    let pubkey: sp_core::ecdsa::Public =
        hex_literal::hex!("029df1e69b8b7c2da2efe0069dc141c2cec0317bf3fd135abaeb69ee33801f5970")
            .into();
    let account_id = account_id_from_evm_pubkey(pubkey).unwrap();
    assert_eq!(
        hex::encode(account_id),
        format!(
            "77bb3d64ea13e4f0beafdd5d92508d4643bb09cb{}",
            hex::encode(b"@evm_address")
        )
    );
}

fn eip712_verify_cert(pubkey: &[u8], cert: &Certificate, signature: &[u8]) -> Result<AccountId> {
    let address = evm_pubkey_to_adderss(pubkey)?;
    let message_hash =
        eip712::hash_cert(&cert.body).or(Err(SignatureVerifyError::Eip712EncodingError))?;
    account_id_from_evm_pubkey(eip712::eip721_verify(address, signature, message_hash.0)?)
}

fn eip712_verify_query(
    pubkey: &[u8],
    query: Query,
    signature: &[u8],
    proxy: bool,
) -> Result<AccountId> {
    let address = evm_pubkey_to_adderss(pubkey)?;
    let message_hash =
        eip712::hash_query(&query, proxy).or(Err(SignatureVerifyError::Eip712EncodingError))?;
    account_id_from_evm_pubkey(eip712::eip721_verify(address, signature, message_hash.0)?)
}

fn non_eip712_verify(
    pubkey: &[u8],
    msg: &[u8],
    signature: &[u8],
    sig_type: SignatureType,
    content_type: u8,
) -> Result<AccountId> {
    let mut buffer = vec![content_type];
    buffer.extend_from_slice(msg);
    let msg = &buffer;
    let signer: AccountId = match sig_type {
        SignatureType::Ed25519 => {
            sub_recover::<sp_core::ed25519::Pair>(pubkey, signature, msg)?.into()
        }
        SignatureType::Sr25519 => {
            sub_recover::<sp_core::sr25519::Pair>(pubkey, signature, msg)?.into()
        }
        SignatureType::Ecdsa => sp_core::blake2_256(
            sub_recover::<sp_core::ecdsa::Pair>(pubkey, signature, msg)?.as_ref(),
        )
        .into(),
        SignatureType::Ed25519WrapBytes => {
            let wrapped = wrap_bytes(msg);
            sub_recover::<sp_core::ed25519::Pair>(&pubkey, signature, &wrapped)?.into()
        }
        SignatureType::Sr25519WrapBytes => {
            let wrapped = wrap_bytes(msg);
            sub_recover::<sp_core::sr25519::Pair>(&pubkey, signature, &wrapped)?.into()
        }
        SignatureType::EcdsaWrapBytes => {
            let wrapped = wrap_bytes(msg);
            sp_core::blake2_256(
                sub_recover::<sp_core::ecdsa::Pair>(&pubkey, signature, &wrapped)?.as_ref(),
            )
            .into()
        }
        SignatureType::EvmEcdsa => account_id_from_evm_pubkey(
            sub_recover::<sp_core::ecdsa::Pair>(&pubkey, signature, msg)?,
        )?,
        SignatureType::EvmEcdsaWrapBytes => {
            let wrapped = wrap_bytes(msg);
            account_id_from_evm_pubkey(sub_recover::<sp_core::ecdsa::Pair>(
                &pubkey, signature, &wrapped,
            )?)?
        }
        SignatureType::Eip712 => {
            return Err(SignatureVerifyError::InvalidSignatureType);
        }
    };
    Ok(signer)
}
