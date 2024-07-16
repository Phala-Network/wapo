use anyhow::Result;
use scale::{Decode, Encode};
use scale_info::TypeInfo;
use schnorrkel::SECRET_KEY_LENGTH;
use sp_core::{sr25519, ByteArray as _, DeriveJunction, Pair as PairT};

use crate::{ContentType, CryptoRng, Error};

type PublicKey = [u8; sr25519::PUBLIC_KEY_SERIALIZED_SIZE];

pub struct Pair {
    pair: sr25519::Pair,
}

#[derive(Clone, Encode, Decode, TypeInfo)]
pub struct Public {
    inner: PublicKey,
}

impl Pair {
    pub fn new() -> Self {
        let seed = rand::thread_rng().crypto_gen();
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

    pub fn derive(&self, path: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let (pair, _seed) = self
            .pair
            .derive(path.into_iter().map(DeriveJunction::Hard), None)
            .expect("derive key should never fail");
        Self { pair }
    }
}

impl Default for Pair {
    fn default() -> Self {
        Self::new()
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
    ) -> Result<(), Error> {
        let final_message = content_type.wrap_message(message);
        let signature =
            sr25519::Signature::from_slice(signature).or(Err(Error::InvalidSignature))?;

        let pubkey = sr25519::Public::from(self.inner);
        if sr25519::Pair::verify(&signature, final_message, &pubkey) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    pub fn to_array(&self) -> PublicKey {
        self.inner
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pair() {
        let pair = Pair::new();
        assert_eq!(pair.dump().len(), SECRET_KEY_LENGTH);
        assert_eq!(
            pair.public().inner.len(),
            sr25519::PUBLIC_KEY_SERIALIZED_SIZE
        );
    }

    #[test]
    fn test_load_pair() {
        let pair = Pair::new();
        let secret_key = pair.dump();
        let loaded_pair = Pair::load(&secret_key).unwrap();
        assert_eq!(loaded_pair.dump(), secret_key);
        assert_eq!(loaded_pair.public().inner, pair.public().inner);
    }

    #[test]
    fn test_sign_and_verify() {
        let pair = Pair::new();
        let content_type = ContentType::RpcResponse;
        let message = b"Hello, world!";
        let signature = pair.sign(content_type, message);
        assert!(pair
            .public()
            .verify(content_type, message, &signature)
            .is_ok());
    }
}
