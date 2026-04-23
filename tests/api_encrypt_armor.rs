use age::secrecy::ExposeSecret;
use age_crypto::{ArmoredData, decrypt_armor, encrypt_armor};
fn generate_test_keys() -> (age::x25519::Identity, String) {
    let id = age::x25519::Identity::generate();
    let recipient = id.to_public().to_string();
    (id, recipient)
}
#[test]
fn test_encrypt_armor_success() {
    let plaintext = b"Hello, Armored Age!";
    let (_id, recipient) = generate_test_keys();
    let result = encrypt_armor(plaintext, &[&recipient]);
    assert!(result.is_ok());
    let armored = result.unwrap();
    assert!(!armored.is_empty());
    assert!(ArmoredData::is_valid_armored(armored.as_str()));
    assert!(armored.as_str().contains("BEGIN AGE ENCRYPTED FILE"));
    assert!(armored.as_str().contains("END AGE ENCRYPTED FILE"));
}
#[test]
fn test_encrypt_armor_and_decrypt_armor_roundtrip() {
    let plaintext = b"Roundtrip armor test";
    let (id, recipient) = generate_test_keys();
    let armored = encrypt_armor(plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt_armor(armored.as_str(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_encrypt_armor_multiple_recipients() {
    let plaintext = b"For multiple armored recipients";
    let (id1, rec1) = generate_test_keys();
    let (id2, rec2) = generate_test_keys();
    let armored = encrypt_armor(plaintext, &[&rec1, &rec2]).unwrap();
    let decrypted1 = decrypt_armor(armored.as_str(), id1.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted1, plaintext);
    let decrypted2 = decrypt_armor(armored.as_str(), id2.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted2, plaintext);
}
#[test]
fn test_encrypt_armor_no_recipients_error() {
    let plaintext = b"test";
    let result = encrypt_armor(plaintext, &[]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        age_crypto::Error::Encrypt(age_crypto::EncryptError::NoRecipients)
    ));
}
#[test]
fn test_encrypt_armor_invalid_recipient() {
    let plaintext = b"test";
    let result = encrypt_armor(plaintext, &["invalid_key"]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        age_crypto::Error::Encrypt(age_crypto::EncryptError::InvalidRecipient { .. })
    ));
}
#[test]
fn test_encrypt_armor_empty_plaintext() {
    let plaintext = b"";
    let (id, recipient) = generate_test_keys();
    let armored = encrypt_armor(plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt_armor(armored.as_str(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, b"");
}
#[test]
fn test_encrypt_armor_large_plaintext() {
    let plaintext = vec![0x42; 500_000];
    let (id, recipient) = generate_test_keys();
    let armored = encrypt_armor(&plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt_armor(armored.as_str(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_encrypt_armor_unicode_plaintext() {
    let plaintext = "Armor 🛡️ with 日本語".as_bytes();
    let (id, recipient) = generate_test_keys();
    let armored = encrypt_armor(plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt_armor(armored.as_str(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_encrypt_armor_duplicate_recipients() {
    let plaintext = b"duplicate recipients";
    let (id, recipient) = generate_test_keys();
    let armored = encrypt_armor(plaintext, &[&recipient, &recipient]).unwrap();
    let decrypted = decrypt_armor(armored.as_str(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
