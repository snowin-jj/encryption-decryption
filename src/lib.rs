use std::num::NonZeroU32;

use ring::aead::{
    Aad,
    AES_256_GCM,
    BoundKey,
    Nonce,
    NONCE_LEN,
    NonceSequence,
    OpeningKey,
    SealingKey,
    UnboundKey,
};
use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA256};
use ring::rand::{SecureRandom, SystemRandom};


/// Aes256GcmEngine is a high-level encryption engine. Once created, it
/// can encrypt and decrypt slices of bytes, using a single parameter to
/// `encrypt_bytes` or `decrypt_bytes`, providing a conceptually simple
/// model of symmetric encryption.
///
/// An Aes256GcmEngine must be initialized with a plaintext password and
/// salt byte slice. The encryption key passed to the SealingKey and
/// OpeningKey is derived from the password using PBKDF2_HMAC_SHA256, in
/// `derive_key_from_pass`. `new` may panic under catastrophic
/// circumstances, namely if 100000 is not a valid u32 or if the system
/// is unable to fill bytes with random values.
///
/// ```
/// use rust_ring_aead::Aes256GcmEngine;
/// let engine = Aes256GcmEngine::new(String::from("my_password"), &[1u8, 2, 3, 4, 5, 6]);
///
/// let payload = [1u8, 2, 3];
/// let encrypted = engine.encrypt_bytes(payload.as_slice()).unwrap();
///
/// assert_eq!(payload.as_slice(), engine.decrypt_bytes(encrypted.as_slice()).unwrap());
/// ```
pub struct Aes256GcmEngine {
    key: [u8; 32],
    counter: InitializedNonceSequence,
}

impl Aes256GcmEngine {
    pub fn new(pass: String, salt: &[u8]) -> Self {
        Self {
            key: derive_key_from_pass(pass, salt),
            counter: InitializedNonceSequence::new(new_iv().unwrap()),
        }
    }

    pub fn encrypt_bytes(&self, payload: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
        let nonce_bytes = self.counter.current();

        let mut sealing_key = SealingKey::new(UnboundKey::new(&AES_256_GCM, &self.key)?, self.counter);
        let mut raw = payload.to_owned();
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut raw)?;

        // Append the nonce to the beginning of the encrypted bytes
        let mut data = nonce_bytes.to_vec();
        data.append(&mut raw);

        Ok(data)
    }

    pub fn decrypt_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
        // Split the incoming bytes at the nonce length
        let (nonce_bytes, bytes) = bytes.split_at(NONCE_LEN);

        let mut opening_key = OpeningKey::new(
            UnboundKey::new(&AES_256_GCM, &self.key)?,
            InitializedNonceSequence::new(nonce_bytes.try_into()?),
        );

        let mut raw = bytes.to_owned();
        let plaintext = opening_key.open_in_place(Aad::empty(), &mut raw)?;

        Ok(plaintext.to_owned())
    }
}

/// InitializedNonceSequence represents a NonceSequence initialized with
/// a random sequence of 12 bytes. These bytes are interpreted as a u128
/// for quick advancement of the counter.
///
/// Allow for copy and clone of this counter to pass to each sealing key.
/// Normally, we would not want to copy a Nonce sequence, since this
/// would lead to duplication of nonces and therefore compromise the
/// security of the encryption. However, here we only copy the nonce
/// sequence so we are able to append the nonce to the resulting
/// ciphertext. Nonces are safe to pass in clear text since they are
/// unique for each invocation, and we do so here so we can decrypt the
/// ciphertext without needing to internally track the nonces used.
#[derive(Copy, Clone)]
struct InitializedNonceSequence(u128);

impl InitializedNonceSequence {
    fn new(iv: [u8; NONCE_LEN]) -> Self {
        let mut bytes = [0u8; 16];
        iv.into_iter().enumerate().for_each(|(i, b)| bytes[i + 4] = b);
        Self(u128::from_be_bytes(bytes))
    }

    // Gets the current nonce so it can be added to ciphertext. This will unwrap the
    // result of `try_into`, which will only fail if the nonce is an invalid u128.
    // This *should* never happen, since [u8; 12] will always be less than a u128
    fn current(&self) -> [u8; 12] {
        self.0.to_be_bytes()[4..].try_into().unwrap()
    }
}

/// Implement a NonceSequence for the InitializedNonce. Each time the sequence
/// is advanced, the current value of the counter is returned, and the counter
/// is incremented by one, mod 2^96. This ensures that any InitializedNonceSequence
/// sequences can use the nonce obtained from ciphertext.
impl NonceSequence for InitializedNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        // Use the current value of the counter as the nonce
        let nonce = Nonce::try_assume_unique_for_key(&self.current())?;
        // Increase the counter for the next invocation.
        // 79228162514264337593543950336 = 2^96, the total number of possible nonces
        self.0 = (self.0 + 1) % 79228162514264337593543950336u128;
        Ok(nonce)
    }
}

// Create a new random initialization vector, or counter, to use in a NonceSequence
fn new_iv() -> Result<[u8; NONCE_LEN], ring::error::Unspecified> {
    let mut nonce_buf = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce_buf)?;
    Ok(nonce_buf)
}

fn derive_key_from_pass(pass: String, salt: &[u8]) -> [u8; 32] {
    // Byte buffer to store derived bytes
    let mut key = [0u8; 32];
    // Derive the key and store in `key`
    derive(PBKDF2_HMAC_SHA256, NonZeroU32::new(100000u32).unwrap(), salt, &pass.as_bytes(), &mut key);

    key
}

#[cfg(test)]
mod test {
    use crate::Aes256GcmEngine;

    #[test]
    fn can_encrypt_and_decrypt_bytes() {
        let salt = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let engine = Aes256GcmEngine::new("key".to_string(), &salt);
        let message = "some message".as_bytes();

        let encrypted = engine.encrypt_bytes(message).unwrap();
        let decrypted = engine.decrypt_bytes(encrypted.as_slice()).unwrap();

        assert_eq!(message, decrypted.as_slice());
    }
}

