use crypto::aead::{AeadDecryptor, AeadEncryptor};
use crypto::aes_gcm::AesGcm;
use rand::Rng;
use rustc_serialize::hex::FromHex;

use core::str;

pub fn generate_key_and_iv() -> (String, String) {
    let mut rng = rand::thread_rng();
    let key_bytes: [u8; 16] = rng.gen();
    let iv_bytes: [u8; 12] = rng.gen();

    let key_hex = hex::encode(&key_bytes);
    let iv_hex = hex::encode(&iv_bytes);

    (key_hex, iv_hex)
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    s.from_hex().unwrap()
}

pub fn encrypt(msg: &str, key: &str, iv: &str, add: &str) -> (String, Vec<u8>) {
    let key_bytes = hex_to_bytes(key);
    let iv_bytes = hex_to_bytes(iv);
    let plain = msg.as_bytes();
    let add_bytes = add.as_bytes();

    let key_size = crypto::aes::KeySize::KeySize128;

    let mut cipher = AesGcm::new(key_size, &key_bytes, &iv_bytes, &add_bytes);
    let mut out: Vec<u8> = vec![0; plain.len()];
    let mut out_tag: Vec<u8> = vec![0; 16];

    cipher.encrypt(plain, &mut out, &mut out_tag);

    let encrypted_hex = hex::encode(out.clone());

    (encrypted_hex, out_tag)
}

pub fn decrypt(
    encrypted_hex: &str,
    key: &str,
    iv: &str,
    add: &str,
    tag: Vec<u8>,
) -> Result<String, &'static str> {
    let key_bytes = hex_to_bytes(key);
    let iv_bytes = hex_to_bytes(iv);
    let encrypted = hex_to_bytes(encrypted_hex);
    let add_bytes = add.as_bytes();

    let key_size = crypto::aes::KeySize::KeySize128;

    let mut decipher = AesGcm::new(key_size, &key_bytes, &iv_bytes, &add_bytes);
    let mut out: Vec<u8> = vec![0; encrypted.len()];

    if decipher.decrypt(&encrypted, &mut out, &tag) {
        Ok(String::from_utf8(out).unwrap())
    } else {
        Err("Decryption failed")
    }
}
