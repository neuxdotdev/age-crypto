use age::secrecy::ExposeSecret;
use age_crypto::{decrypt, encrypt};
fn generate_test_keys() -> (age::x25519::Identity, String) {
    let id = age::x25519::Identity::generate();
    let recipient = id.to_public().to_string();
    (id, recipient)
}
#[test]
fn test_encrypt_success() {
    let plaintext = b"Hello, Age!";
    let (_id, recipient) = generate_test_keys();
    let result = encrypt(plaintext, &[&recipient]);
    assert!(result.is_ok());
    let encrypted = result.unwrap();
    assert!(!encrypted.is_empty());
    assert_eq!(encrypted.len(), encrypted.as_bytes().len());
}
#[test]
fn test_encrypt_and_decrypt() {
    let plaintext = b"Secret message";
    let (id, recipient) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&recipient]).unwrap();
    let secret_key = id.to_string();
    let decrypted = decrypt(encrypted.as_bytes(), secret_key.expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_encrypt_multiple_recipients() {
    let plaintext = b"For multiple eyes";
    let (id1, rec1) = generate_test_keys();
    let (id2, rec2) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&rec1, &rec2]).unwrap();
    let decrypted1 = decrypt(encrypted.as_bytes(), id1.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted1, plaintext);
    let decrypted2 = decrypt(encrypted.as_bytes(), id2.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted2, plaintext);
}
#[test]
fn test_encrypt_no_recipients_error() {
    let plaintext = b"test";
    let result = encrypt(plaintext, &[]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        age_crypto::Error::Encrypt(age_crypto::EncryptError::NoRecipients)
    ));
    assert_eq!(err.to_string(), "Encrypt error: No recipients provided");
}
#[test]
fn test_encrypt_invalid_recipient() {
    let plaintext = b"test";
    let invalid_recipient = "invalid_key";
    let result = encrypt(plaintext, &[invalid_recipient]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        age_crypto::Error::Encrypt(age_crypto::EncryptError::InvalidRecipient { .. })
    ));
    assert!(err.to_string().contains("Invalid recipient"));
}
#[test]
fn test_encrypt_empty_plaintext() {
    let plaintext = b"";
    let (id, recipient) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&recipient]).unwrap();
    assert!(!encrypted.is_empty());
    let decrypted = decrypt(encrypted.as_bytes(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, b"");
}
#[test]
fn test_encrypt_large_plaintext() {
    let plaintext = vec![0x42; 1024 * 1024];
    let (id, recipient) = generate_test_keys();
    let encrypted = encrypt(&plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt(encrypted.as_bytes(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_encrypt_unicode_plaintext() {
    let plaintext = "Hello 世界 🦀".as_bytes();
    let (id, recipient) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt(encrypted.as_bytes(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_encrypt_multiple_recipients_one_invalid() {
    let plaintext = b"test";
    let (_id, valid_rec) = generate_test_keys();
    let invalid_rec = "not_a_valid_key";
    let result = encrypt(plaintext, &[&valid_rec, invalid_rec]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        age_crypto::Error::Encrypt(age_crypto::EncryptError::InvalidRecipient { .. })
    ));
}
#[test]
fn test_encrypt_with_duplicate_recipients() {
    let plaintext = b"test";
    let (id, recipient) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&recipient, &recipient]).unwrap();
    let decrypted = decrypt(encrypted.as_bytes(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
