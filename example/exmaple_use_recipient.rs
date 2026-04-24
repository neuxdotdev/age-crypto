
use age_setup::build_keypair;
use age_crypto::{encrypt, decrypt};
use std::error::Error;
fn main() -> Result<(), Box<dyn Error>> {
    let alice = build_keypair().map_err(|e| format!("Alice's key generation failed: {}", e))?;
    let bob   = build_keypair().map_err(|e| format!("Bob's key generation failed: {}", e))?;
    let carol = build_keypair().map_err(|e| format!("Carol's key generation failed: {}", e))?;
    let plaintext = b"Company-wide secret";
    let recipients = [
        alice.public.expose(),
        bob.public.expose(),
        carol.public.expose(),
    ];
    let encrypted = encrypt(plaintext, &recipients)?;
    let dec_alice = decrypt(encrypted.as_bytes(), alice.secret.expose())?;
    let dec_bob   = decrypt(encrypted.as_bytes(), bob.secret.expose())?;
    let dec_carol = decrypt(encrypted.as_bytes(), carol.secret.expose())?;
    assert_eq!(dec_alice, plaintext);
    assert_eq!(dec_bob, plaintext);
    assert_eq!(dec_carol, plaintext);
    println!("Multi-recipient encryption works: {} bytes", plaintext.len());
    Ok(())
}