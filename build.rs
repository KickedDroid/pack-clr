use crypto::symmetriccipher::SynchronousStreamCipher;
use std::{fs, io::Write};

fn main() {
    // Create the key 
    let mut file = match std::fs::File::create_new("keyfile") {
        Ok(f) => f,
        Err(_) => {
            std::fs::remove_file("keyfile").expect("Failed to remove file");
            std::fs::File::create_new("keyfile").unwrap()
        }
    }; 
    let key = generate_random_string(256);
    file.write(key.as_bytes()).expect("Failed to write key");

    // Encrypt the payload
    let file = fs::read("src/unencrypted").unwrap();
    let mut cipher = crypto::rc4::Rc4::new(key.as_bytes());
    let mut o = file.clone();
    cipher.process(&file[..], &mut o);
    let _ = fs::write("src/encr", o);
}



use rand::{Rng, rng};
fn generate_random_string(length: usize) -> String {
    let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let mut rng = rng();

    let random_string: String = (0..length)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());

            char::from(charset[idx])
        })
        .collect();

    random_string
}
