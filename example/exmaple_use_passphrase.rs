
use age_crypto::{encrypt_with_passphrase, decrypt_with_passphrase};
use std::error::Error;
fn main() -> Result<(), Box<dyn Error>> {
    let plaintext = b"Personal backup data";
    let passphrase = "correct horse battery staple";
    let encrypted = encrypt_with_passphrase(plaintext, passphrase)?;
    let decrypted = decrypt_with_passphrase(encrypted.as_bytes(), passphrase)?;
    assert_eq!(decrypted, plaintext);
    println!("Passphrase-based encryption roundtrip OK: {} bytes", decrypted.len());
    Ok(())
}