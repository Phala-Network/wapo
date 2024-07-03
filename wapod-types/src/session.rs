use alloc::vec::Vec;
use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::{crypto::verify::verify_message, crypto::CryptoProvider, ContentType};

#[derive(Debug, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, PartialEq, Eq)]
pub struct SessionUpdate {
    pub session: [u8; 32],
    pub seed: [u8; 32],
}

impl SessionUpdate {
    pub fn from_seed<Crypto: CryptoProvider>(seed: [u8; 32], nonce: &[u8]) -> Self {
        let session = Crypto::blake2b_256(&[&seed, nonce].concat());
        Self { session, seed }
    }
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub struct SignedSessionUpdate {
    pub update: SessionUpdate,
    pub signature: Vec<u8>,
}

impl SignedSessionUpdate {
    pub fn verify<Crypto: CryptoProvider>(&self, public_key: &[u8]) -> bool {
        let message = self.update.encode();
        verify_message::<Crypto>(
            ContentType::SessionUpdate,
            &message,
            &self.signature,
            public_key,
        )
    }
}
