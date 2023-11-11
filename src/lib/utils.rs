use ring::rand::{SecureRandom, SystemRandom};

pub fn get_env_or_random(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        // Fill an array with random bytes
        let mut buf = [0u8; 12];
        SystemRandom::new().fill(&mut buf).unwrap();

        // hex encode the value so it can be represented as a string
        let encoded = hex::encode(&buf);
        eprintln!(
            "{} env var is not set. Using a random default value: {}",
            name, encoded
        );
        encoded
    })
}
