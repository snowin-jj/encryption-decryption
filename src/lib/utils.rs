use orion::aead::{self, SecretKey};

pub fn encrypt(plaintext: &str) -> (String, String) {
    let secret_key = aead::SecretKey::default();
    let cipher = aead::seal(&secret_key, plaintext.as_bytes()).unwrap();

    let ciphertext = hex::encode(cipher);
    let key = hex::encode(secret_key.unprotected_as_bytes());

    (ciphertext, key)
}

pub fn decrypt(ciphertext: String, key: String) -> String {
    let decoded_key = hex::decode(key);
    let cipher = hex::decode(ciphertext).unwrap();

    let secret_key = SecretKey::from_slice(decoded_key.unwrap().as_slice()).unwrap();
    let plaintext_bytes = aead::open(&secret_key, cipher.as_slice()).unwrap();

    let plaintext = String::from_utf8(plaintext_bytes).unwrap();
    return plaintext;
}
