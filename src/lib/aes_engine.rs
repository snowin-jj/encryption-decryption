use std::num::NonZeroU32;

use ring::{
    aead::{
        self, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, AES_256_GCM, NONCE_LEN,
    },
    pbkdf2::{derive, PBKDF2_HMAC_SHA256},
    rand::{SecureRandom, SystemRandom},
};

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

    pub fn encrypt_bytes(&self, payload: &[u8]) -> Result<String, ring::error::Unspecified> {
        let nonce_bytes = self.counter.current();

        let mut sealing_key =
            aead::SealingKey::new(UnboundKey::new(&AES_256_GCM, &self.key)?, self.counter);
        let mut raw = payload.to_owned();
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut raw)?;

        // Append the nonce to the beginning of the encrypted bytes
        let mut data = nonce_bytes.to_vec();
        data.append(&mut raw);

        Ok(hex::encode(data))
    }

    pub fn decrypt_bytes(&self, cipher: &String) -> Result<String, ring::error::Unspecified> {
        let bytes = hex::decode(cipher).unwrap();
        // Split the incoming bytes at the nonce length
        let (nonce_bytes, bytes) = bytes.split_at(NONCE_LEN);

        let mut opening_key = OpeningKey::new(
            UnboundKey::new(&AES_256_GCM, &self.key)?,
            InitializedNonceSequence::new(nonce_bytes.try_into()?),
        );

        let mut raw = bytes.to_owned();
        let plaintext = opening_key.open_in_place(Aad::empty(), &mut raw)?;

        Ok(String::from_utf8_lossy(plaintext).to_string())
    }
}

#[derive(Copy, Clone)]
struct InitializedNonceSequence(u128);

impl InitializedNonceSequence {
    fn new(iv: [u8; NONCE_LEN]) -> Self {
        let mut bytes = [0u8; 16];
        iv.into_iter()
            .enumerate()
            .for_each(|(i, b)| bytes[i + 4] = b);
        Self(u128::from_be_bytes(bytes))
    }

    fn current(&self) -> [u8; 12] {
        self.0.to_be_bytes()[4..].try_into().unwrap()
    }
}

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
    derive(
        PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100000u32).unwrap(),
        salt,
        &pass.as_bytes(),
        &mut key,
    );

    key
}
