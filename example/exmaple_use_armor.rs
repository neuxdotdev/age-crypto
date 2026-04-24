
use age_setup::build_keypair;
use age_crypto::{encrypt_armor, decrypt_armor};
use std::error::Error;
fn main() -> Result<(), Box<dyn Error>> {
    let keypair = build_keypair().map_err(|e| format!("Key generation failed: {}", e))?;
    let plaintext = b"Data safe for text transport";
    let armored = encrypt_armor(plaintext, &[keypair.public.expose()])?;
    println!("Armored ciphertext (first 80 chars):\n{}", &armored.as_str()[..80]);
    let decrypted = decrypt_armor(armored.as_str(), keypair.secret.expose())?;
    assert_eq!(decrypted, plaintext);
    println!("Decryption successful: {} bytes", decrypted.len());
    Ok(())
}