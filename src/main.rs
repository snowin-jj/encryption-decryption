#[path = "./lib/mod.rs"]
mod lib;

use crate::lib::{aes_engine::Aes256GcmEngine, utils::get_env_or_random};

fn main() {
    // Get password from environment or set a default
    let pass = get_env_or_random("PASS");
    // Get salt from environment or set a default
    let salt = get_env_or_random("SALT");

    let engine = Aes256GcmEngine::new(pass, salt.as_bytes());

    let plaintext = "snowin";
    let cipher = &engine.encrypt_bytes(plaintext.as_bytes()).unwrap();
    println!("cipher text: {:?}", cipher);

    let decrypted_text = &engine.decrypt_bytes(cipher).unwrap();
    println!("decrypted text: {:?}", decrypted_text)
}
