use lib::utils::encrypt;

use crate::lib::utils::{decrypt, generate_key_and_iv};

#[path = "./lib/mod.rs"]
mod lib;

fn main() {
    let plaintext = "snowin";
    let (key, iv) = generate_key_and_iv();

    let (encrypted_text, out_tag) = encrypt(plaintext, &key, &iv, "");
    println!("encrypted_text: {}", encrypted_text);

    let decrypt_text = decrypt(&encrypted_text, &key, &iv, "", out_tag);
    match decrypt_text {
        Ok(text) => println!("decrypted_text: {}", text),
        Err(e) => println!("Error: {}", e),
    }
}
