use age_crypto::{
    decrypt, decrypt_armor, decrypt_with_passphrase, decrypt_with_passphrase_armor, encrypt,
    encrypt_armor, encrypt_with_passphrase, encrypt_with_passphrase_armor,
};
use age_setup::build_keypair;
use std::error::Error;
fn main() -> Result<(), Box<dyn Error>> {
    let keypair = build_keypair()?;
    println!("Public key:  {}", keypair.public);
    println!("Secret key:  {}\n", keypair.secret);
    let plaintext = b"Hello, age-crypto! This is a secret message.";
    let encrypted_bin = encrypt(plaintext, &[keypair.public.expose()])?;
    let decrypted_bin = decrypt(encrypted_bin.as_bytes(), keypair.secret.expose_secret())?;
    assert_eq!(plaintext, &decrypted_bin[..]);
    println!("✅ Key-based binary roundtrip OK");
    let armored = encrypt_armor(plaintext, &[keypair.public.expose()])?;
    let decrypted_armor = decrypt_armor(armored.as_str(), keypair.secret.expose_secret())?;
    assert_eq!(plaintext, &decrypted_armor[..]);
    println!("✅ Key-based armored roundtrip OK");
    let pass = "correct-horse-battery-staple";
    let encrypted_pass_bin = encrypt_with_passphrase(plaintext, pass)?;
    let decrypted_pass_bin = decrypt_with_passphrase(encrypted_pass_bin.as_bytes(), pass)?;
    assert_eq!(plaintext, &decrypted_pass_bin[..]);
    println!("✅ Passphrase-based binary roundtrip OK");
    let armored_pass = encrypt_with_passphrase_armor(plaintext, pass)?;
    let decrypted_pass_armor = decrypt_with_passphrase_armor(armored_pass.as_str(), pass)?;
    assert_eq!(plaintext, &decrypted_pass_armor[..]);
    println!("✅ Passphrase-based armored roundtrip OK");
    println!("\n🎉 All tests passed successfully!");
    Ok(())
}
