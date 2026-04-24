use age_crypto::{encrypt_with_passphrase_armor, decrypt_with_passphrase_armor};
use std::error::Error;
fn main() -> Result<(), Box<dyn Error>> {
    let plaintext = b"QR-code content: https://example.com";
    let pass = "my-secret-armor-pass";
    let armored = encrypt_with_passphrase_armor(plaintext, pass)?;
    println!("Armored output (first line): {}", armored.lines().next().unwrap());
    let decrypted = decrypt_with_passphrase_armor(&armored, pass)?;
    assert_eq!(decrypted, plaintext);
    println!("Passphrase + armor roundtrip OK: {} bytes", decrypted.len());
    Ok(())
}