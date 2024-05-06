use alloc::vec::Vec;
use scale::{Decode, Encode};
use scale_info::TypeInfo;
use schnorrkel::SECRET_KEY_LENGTH;
use sp_core::{sr25519, ByteArray as _, Pair as PairT};

use crate::ContentType;

type PublicKey = [u8; sr25519::PUBLIC_KEY_SERIALIZED_SIZE];

pub enum CryptoError {
    InvalidSignature,
}

pub struct Pair {
    pair: sr25519::Pair,
}

#[derive(Clone, Encode, Decode, TypeInfo)]
pub struct Public {
    inner: PublicKey,
}

impl Pair {
    pub fn new() -> Self {
        use rand::Rng;
        let seed = rand::thread_rng().gen();
        let pair = sr25519::Pair::from_seed(&seed);
        Self { pair }
    }

    pub fn dump(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.pair.as_ref().secret.to_bytes()
    }

    pub fn load(secret: &[u8; SECRET_KEY_LENGTH]) -> Option<Self> {
        let pair = sr25519::Pair::from_seed_slice(secret).ok()?;
        Some(Self { pair })
    }

    pub fn public(&self) -> Public {
        Public {
            inner: self.pair.public().0,
        }
    }

    pub fn sign(&self, content_type: ContentType, message: impl AsRef<[u8]>) -> Vec<u8> {
        let final_message = content_type.wrap_message(message);
        self.pair.sign(&final_message).0.to_vec()
    }
}

impl Encode for Pair {
    fn encode_to<W: scale::Output + ?Sized>(&self, dest: &mut W) {
        self.dump().encode_to(dest);
    }
}

impl Decode for Pair {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let secret = Decode::decode(input)?;
        Self::load(&secret).ok_or(scale::Error::from("Invalid secret key"))
    }
}

impl Public {
    pub fn verify(
        &self,
        content_type: ContentType,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let final_message = content_type.wrap_message(message);
        let signature =
            sr25519::Signature::from_slice(signature).or(Err(CryptoError::InvalidSignature))?;

        let pubkey = sr25519::Public::from(self.inner);
        if sr25519::Pair::verify(&signature, &final_message, &pubkey) {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }
}

impl AsRef<[u8]> for Public {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsRef<PublicKey> for Public {
    fn as_ref(&self) -> &PublicKey {
        &self.inner
    }
}
