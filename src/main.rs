use std::io::stdin;

use ring::rand::{SecureRandom, SystemRandom};
use rust_ring_aead::Aes256GcmEngine;

const USAGE: &str = "Welcome to this encryption example!

Enter a command, either 'encrypt' or 'decrypt' followed by the
data to do the command on.

During encryption, the resulting data will be hex-encoded
and printed to your terminal.

During decryption, the input data will be decoded from hex
and then decrypted. The result will be printed to the terminal
in plaintext.
";

fn get_env_or_random(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        // Fill an array with random bytes
        let mut buf = [0u8; 12];
        SystemRandom::new().fill(&mut buf).unwrap();

        // hex encode the value so it can be represented as a string
        let encoded = hex::encode(&buf);
        eprintln!("{} env var is not set. Using a random default value: {}", name, encoded);
        encoded
    })
}

// Encrypt data using engine and convert to hex encoding
// Map errors to readable strings for the user
fn cmd_encrypt(engine: &Aes256GcmEngine, data: &str) -> Result<String, String> {
    let encrypted = engine.encrypt_bytes(data.trim().as_bytes())
        .map_err(|_| "Encryption error".to_string())?;

    Ok(hex::encode(encrypted.as_slice()))
}

// Decrypt data using engine and convert to hex encoding
// Map errors to readable strings for the user
fn cmd_decrypt(engine: &Aes256GcmEngine, data: &str) -> Result<String, String> {
    let bytes = hex::decode(data.trim())
        .map_err(|_| "Invalid hex string".to_string())?;

    let result = engine.decrypt_bytes(bytes.as_slice())
        .map_err(|_| "Decryption error".to_string())?;

    Ok(String::from_utf8(result).map_err(|_| "Invalid UT8-string".to_string())?)
}

fn main() {
    // Get password from environment or set a default
    let pass = get_env_or_random("PASS");

    // Get salt from environment or set a default
    let salt = get_env_or_random("SALT");

    // Initialize the engine with our password and salt
    let engine = Aes256GcmEngine::new(pass, salt.as_bytes());

    // Print usage of the program
    println!("{}", USAGE);

    // Start a REPL which will encrypt or decrypt values.
    loop {
        // Read the next line of input
        let mut line = String::new();
        stdin().read_line(&mut line).expect("Unable to read from stdin");

        // Split into the command and the data
        let result = match line.splitn(2, " ").collect::<Vec<&str>>()[..] {
            ["encrypt", data] => cmd_encrypt(&engine, data),
            ["decrypt", data] => cmd_decrypt(&engine, data),
            _ => Err("Must provide input as '[cmd] [data]'. Ignoring input".to_string())
        };

        match result {
            Ok(msg) => println!("{}", msg),
            Err(msg) => eprintln!("{}", msg)
        }
    }
}
