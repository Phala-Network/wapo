use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::{
    crypto::{
        verify::{verify_message, Verifiable},
        CryptoProvider, Signature,
    },
    primitives::{BoundedVec, WorkerPubkey},
    Address, ContentType,
};

#[derive(Debug, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, PartialEq, Eq)]
pub struct SessionUpdate {
    pub session: [u8; 32],
    pub seed: [u8; 32],
    pub reward_receiver: BoundedVec<u8, 32>,
}

impl SessionUpdate {
    pub fn session_from_seed<Crypto: CryptoProvider>(seed: [u8; 32], nonce: &[u8]) -> [u8; 32] {
        Crypto::blake2b_256(&[&seed, nonce].concat())
    }

    pub fn new<Crypto: CryptoProvider>(
        seed: [u8; 32],
        nonce: &[u8],
        reward_receiver: Address,
    ) -> Self {
        let session = Self::session_from_seed::<Crypto>(seed, nonce);
        Self {
            session,
            seed,
            reward_receiver: reward_receiver.to_vec().into(),
        }
    }
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub struct SignedSessionUpdate {
    pub update: SessionUpdate,
    pub signature: Signature,
    pub public_key: WorkerPubkey,
}

impl Verifiable for SignedSessionUpdate {
    fn verify<Crypto: CryptoProvider>(&self) -> bool {
        let message = self.update.encode();
        verify_message::<Crypto>(
            ContentType::SessionUpdate,
            &message,
            &self.signature,
            &self.public_key,
        )
    }
}
