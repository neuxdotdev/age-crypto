
use age_setup::build_keypair;
use age_crypto::encrypt;
use std::error::Error;
fn main() -> Result<(), Box<dyn Error>> {
    let keypair = build_keypair().map_err(|e| format!("Key generation failed: {}", e))?;
    let plaintext = b"Secret message for a single recipient";
    let encrypted = encrypt(plaintext, &[keypair.public.expose()])?;
    println!("Public key: {}", keypair.public);
    println!("Ciphertext length: {} bytes", encrypted.len());
    Ok(())
}