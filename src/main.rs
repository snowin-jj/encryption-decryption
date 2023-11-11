#[path = "./lib/mod.rs"]
mod lib;

use crate::lib::utils::{decrypt, encrypt};

fn main() {
    let plaintext = "snowin";
    println!("plaintext: {:?}", plaintext);

    let (cipher, key) = encrypt(plaintext);
    println!("cipher text: {:?}", cipher);
    println!("key: {:?}", key);

    let decrypted_text = decrypt(cipher, key);
    println!("decrypted text: {:?}", decrypted_text)
}
