use crate::Error;

use ring::aead::{LessSafeKey, UnboundKey};

type Result<T> = core::result::Result<T, Error>;

// aes-256-gcm key
pub struct AeadKey(LessSafeKey);

pub const IV_BYTES: usize = 12;
pub type IV = [u8; IV_BYTES];

/// Generates a random IV
pub fn generate_iv() -> IV {
    use ring::rand::SecureRandom;
    let mut nonce_vec = [0_u8; IV_BYTES];
    let rand = ring::rand::SystemRandom::new();
    rand.fill(&mut nonce_vec).expect("Failed to generate IV");
    nonce_vec
}

fn load_key(raw: &[u8]) -> Result<AeadKey> {
    let unbound_key =
        UnboundKey::new(&ring::aead::AES_256_GCM, raw).map_err(|_| Error::InvalidAeadKey)?;
    Ok(AeadKey(LessSafeKey::new(unbound_key)))
}

// Encrypts the data in-place and appends a 128bit auth tag
pub fn encrypt(iv: &IV, secret: &[u8], in_out: &mut Vec<u8>) -> Result<()> {
    let nonce = ring::aead::Nonce::assume_unique_for_key(*iv);
    let key = load_key(secret)?;

    key.0
        .seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), in_out)
        .map_err(|_| Error::CryptoError)?;
    Ok(())
}

// Decrypts the cipher (with 128 auth tag appended) in-place and returns the message as a slice.
pub fn decrypt<'in_out>(
    iv: &[u8],
    secret: &[u8],
    in_out: &'in_out mut [u8],
) -> Result<&'in_out mut [u8]> {
    let mut iv_arr = [0_u8; IV_BYTES];
    iv_arr.copy_from_slice(&iv[..IV_BYTES]);
    let key = load_key(secret)?;
    let nonce = ring::aead::Nonce::assume_unique_for_key(iv_arr);

    key.0
        .open_in_place(nonce, ring::aead::Aad::empty(), in_out)
        .map_err(|_| Error::CryptoError)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encrypt_and_decrypt() {
        let iv = generate_iv();
        let secret = [233_u8; 32];
        let message = [233_u8; 64];

        let mut encrypted_message = Vec::new();
        encrypted_message.extend_from_slice(&message);

        encrypt(&iv, &secret, &mut encrypted_message).unwrap();
        let decrypted_messgae = decrypt(&iv, &secret, &mut encrypted_message[..]).unwrap();

        assert_eq!(decrypted_messgae, message);
    }
}
