use curve25519_dalek::Scalar;
use schnorrkel::PublicKey;

use crate::aead;
use crate::sr25519::Pair;

use crate::Error;

impl Pair {
    /// Derives a secret key for symmetric encryption without a KDF
    ///
    /// `pk` must be in compressed version.
    fn ecdh_agree(&self, pk: &[u8]) -> Result<Vec<u8>, Error> {
        // The first 32 bytes holds the canonical private key
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.dump()[0..32]);
        let key =
            Scalar::from_canonical_bytes(key).expect("This should never fail with correct seed");
        let public = PublicKey::from_bytes(pk).or(Err(Error::InvalidPublicKey))?;
        Ok((key * public.as_point()).compress().0.to_vec())
    }

    // Encrypts a message using ECDH shared secret
    pub fn encrypt_message(&self, receiver: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
        let shared_secret = self.ecdh_agree(receiver)?;
        let iv = aead::generate_iv();
        let mut message = message.to_vec();
        aead::encrypt(&iv, &shared_secret, &mut message)?;
        Ok([&iv[..], &message].concat())
    }

    // Decrypts a message using ECDH shared secret
    pub fn decrypt_message(&self, sender: &[u8], message: &mut [u8]) -> Result<Vec<u8>, Error> {
        if message.len() < aead::IV_BYTES {
            return Err(Error::InvalidMessage);
        }
        let shared_secret = self.ecdh_agree(sender)?;
        let (iv, body) = message.split_at_mut(aead::IV_BYTES);
        let iv = iv.try_into().expect("IV length is correct");
        let decrypted = aead::decrypt(iv, &shared_secret, body)?;
        Ok(decrypted.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_sent_message() {
        let pair = Pair::new();
        let message = vec![6, 7, 8, 9, 10];

        let mut encrypted = pair
            .encrypt_message(pair.public().as_bytes(), &message)
            .unwrap();
        let decrypted = pair
            .decrypt_message(pair.public().as_bytes(), &mut encrypted)
            .unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decrypt_message() {
        let alice = Pair::new();
        let bob = Pair::new();
        let message = vec![6, 7, 8, 9, 10];

        let mut encrypted = alice
            .encrypt_message(bob.public().as_bytes(), &message)
            .unwrap();
        let decrypted = bob
            .decrypt_message(alice.public().as_bytes(), &mut encrypted)
            .unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decrypt_message_invalid_message() {
        let pair = Pair::new();
        let sender = vec![1, 2, 3, 4, 5];
        let mut message = vec![6, 7, 8, 9, 10];

        // Modify the message length to be less than IV_BYTES
        message.truncate(aead::IV_BYTES - 1);

        let result = pair.decrypt_message(&sender, &mut message);

        assert_eq!(result, Err(Error::InvalidMessage));
    }
}
