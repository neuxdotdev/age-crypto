
use age_setup::build_keypair;
use age_crypto::{encrypt, decrypt};
use std::error::Error;
fn main() -> Result<(), Box<dyn Error>> {
    let keypair = build_keypair().map_err(|e| format!("Key generation failed: {}", e))?;
    let plaintext = b"Top secret data";
    let encrypted = encrypt(plaintext, &[keypair.public.expose()])?;
    let decrypted = decrypt(encrypted.as_bytes(), keypair.secret.expose())?;
    assert_eq!(decrypted, plaintext);
    println!("Decryption succeeded: {} bytes", decrypted.len());
    Ok(())
}