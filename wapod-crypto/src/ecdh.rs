use curve25519_dalek::scalar::Scalar;
use schnorrkel::keys::{ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey};
use schnorrkel::{MINI_SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

use crate::{sr25519, Error};

type Result<T> = std::result::Result<T, Error>;

/// sr25519 key pair
#[derive(Clone)]
pub struct EcdhKey(Keypair);

pub type EcdhSecretKey = [u8; SECRET_KEY_LENGTH]; // 32 privkey, 32 nonce
pub type EcdhPublicKey = [u8; PUBLIC_KEY_LENGTH]; // 32 compressed pubkey

pub type Seed = [u8; MINI_SECRET_KEY_LENGTH]; // 32 seed

impl EcdhKey {
    pub fn create(seed: &Seed) -> Result<EcdhKey> {
        Ok(EcdhKey(
            MiniSecretKey::from_bytes(seed)
                .map_err(|_| Error::InvalidSecretKey)?
                .expand_to_keypair(ExpansionMode::Ed25519),
        ))
    }

    pub fn from_sr25519_pair(pair: &sr25519::Pair) -> Self {
        Self::from_secret(&pair.dump()).expect("This should never fail with valid key pair")
    }

    pub fn from_secret(secret: &EcdhSecretKey) -> Result<EcdhKey> {
        Ok(EcdhKey(
            SecretKey::from_bytes(secret.as_ref())
                .map_err(|_| Error::InvalidSecretKey)?
                .to_keypair(),
        ))
    }

    pub fn public(&self) -> EcdhPublicKey {
        self.0.public.to_bytes()
    }

    pub fn secret(&self) -> EcdhSecretKey {
        self.0.secret.to_bytes()
    }

    /// Derives a secret key for symmetric encryption without a KDF
    ///
    /// `pk` must be in compressed version.
    pub fn agree(&self, pk: &[u8]) -> Result<Vec<u8>> {
        // The first 32 bytes holds the canonical private key
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.secret()[0..32]);
        let key =
            Scalar::from_canonical_bytes(key).expect("This should never fail with correct seed");
        let public = PublicKey::from_bytes(pk).or(Err(Error::InvalidPublicKey))?;
        Ok((key * public.as_point()).compress().0.to_vec())
    }
}

impl sr25519::Pair {
    pub fn to_ecdh_key(&self) -> EcdhKey {
        EcdhKey::from_sr25519_pair(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn generate_key() -> EcdhKey {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut seed: Seed = [0_u8; MINI_SECRET_KEY_LENGTH];

        rng.fill_bytes(&mut seed);

        EcdhKey::create(&seed).unwrap()
    }

    #[test]
    fn ecdh_key_clone() {
        let key1 = generate_key();
        let key2 = key1.clone();
        let key3 = EcdhKey::from_secret(&key1.secret()).unwrap();

        assert_eq!(key1.secret(), key2.secret());
        assert_eq!(key1.secret(), key3.secret());
    }

    #[test]
    fn ecdh_agree() {
        let key1 = generate_key();
        let key2 = generate_key();
        assert_eq!(
            key1.agree(key2.public().as_ref()).unwrap(),
            key2.agree(key1.public().as_ref()).unwrap(),
        )
    }
}
