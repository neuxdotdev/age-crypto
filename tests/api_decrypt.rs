use age::secrecy::ExposeSecret;
use age_crypto::{decrypt, encrypt};
fn generate_test_keys() -> (age::x25519::Identity, String) {
    let id = age::x25519::Identity::generate();
    let recipient = id.to_public().to_string();
    (id, recipient)
}
fn generate_dummy_ciphertext() -> Vec<u8> {
    let (_id, recipient) = generate_test_keys();
    let plaintext = b"dummy data";
    encrypt(plaintext, &[&recipient]).unwrap().to_vec()
}
#[test]
fn test_decrypt_success() {
    let plaintext = b"Secret message for decrypt";
    let (id, recipient) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt(encrypted.as_bytes(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_decrypt_wrong_key() {
    let plaintext = b"Secret message";
    let (_id, recipient) = generate_test_keys();
    let (wrong_id, _) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&recipient]).unwrap();
    let result = decrypt(encrypted.as_bytes(), wrong_id.to_string().expose_secret());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        age_crypto::Error::Decrypt(age_crypto::DecryptError::Failed(_))
    ));
    assert!(
        err.to_string().contains("Decryption failed")
            || err.to_string().contains("no matching secret key")
    );
}
#[test]
fn test_decrypt_invalid_ciphertext() {
    let invalid_ciphertext = b"this is not a valid age ciphertext";
    let (id, _) = generate_test_keys();
    let result = decrypt(invalid_ciphertext, id.to_string().expose_secret());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        age_crypto::Error::Decrypt(age_crypto::DecryptError::InvalidCiphertext(_))
    ));
    assert!(err.to_string().contains("Invalid ciphertext"));
}
#[test]
fn test_decrypt_invalid_identity() {
    let encrypted = generate_dummy_ciphertext();
    let invalid_key = "not a valid x25519 key";
    let result = decrypt(&encrypted, invalid_key);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        age_crypto::Error::Decrypt(age_crypto::DecryptError::InvalidIdentity(_))
    ));
    assert!(err.to_string().contains("Invalid identity"));
}
#[test]
fn test_decrypt_empty_ciphertext() {
    let empty_ciphertext = &[];
    let (id, _) = generate_test_keys();
    let result = decrypt(empty_ciphertext, id.to_string().expose_secret());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        age_crypto::Error::Decrypt(age_crypto::DecryptError::InvalidCiphertext(_))
    ));
}
#[test]
fn test_decrypt_corrupted_ciphertext() {
    let mut encrypted = generate_dummy_ciphertext();
    if encrypted.len() > 5 {
        encrypted[5] ^= 0xFF;
    }
    let (id, _) = generate_test_keys();
    let result = decrypt(&encrypted, id.to_string().expose_secret());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("ciphertext") || err.to_string().contains("decrypt"));
}
#[test]
fn test_decrypt_large_data() {
    let plaintext = vec![0xCD; 2 * 1024 * 1024];
    let (id, recipient) = generate_test_keys();
    let encrypted = encrypt(&plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt(encrypted.as_bytes(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_decrypt_unicode_plaintext() {
    let plaintext = "🦀 Rust ❤️ age".as_bytes();
    let (id, recipient) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt(encrypted.as_bytes(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_decrypt_with_multiple_recipients_any_key() {
    let plaintext = b"Shared secret";
    let (id1, rec1) = generate_test_keys();
    let (id2, rec2) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&rec1, &rec2]).unwrap();
    let decrypted1 = decrypt(encrypted.as_bytes(), id1.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted1, plaintext);
    let decrypted2 = decrypt(encrypted.as_bytes(), id2.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted2, plaintext);
}
#[test]
fn test_decrypt_after_serialization_roundtrip() {
    let plaintext = b"Roundtrip test";
    let (id, recipient) = generate_test_keys();
    let encrypted = encrypt(plaintext, &[&recipient]).unwrap();
    let serialized = encrypted.to_vec();
    let decrypted = decrypt(&serialized, id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
