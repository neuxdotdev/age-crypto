use age::secrecy::ExposeSecret;
use age_crypto::{decrypt_armor, encrypt_armor};
fn generate_test_keys() -> (age::x25519::Identity, String) {
    let id = age::x25519::Identity::generate();
    let recipient = id.to_public().to_string();
    (id, recipient)
}
fn generate_dummy_armored() -> String {
    let (_id, recipient) = generate_test_keys();
    let plaintext = b"dummy";
    encrypt_armor(plaintext, &[&recipient]).unwrap().to_string()
}
#[test]
fn test_decrypt_armor_success() {
    let plaintext = b"Secret armor data";
    let (id, recipient) = generate_test_keys();
    let armored = encrypt_armor(plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt_armor(armored.as_str(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_decrypt_armor_wrong_key() {
    let (_id, recipient) = generate_test_keys();
    let (wrong_id, _) = generate_test_keys();
    let armored = encrypt_armor(b"secret", &[&recipient]).unwrap();
    let result = decrypt_armor(armored.as_str(), wrong_id.to_string().expose_secret());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        age_crypto::Error::Decrypt(age_crypto::DecryptError::Failed(_))
    ));
}
#[test]
fn test_decrypt_armor_invalid_armored_string() {
    let invalid_armored = "-----BEGIN WRONG-----\ninvalid\n-----END WRONG-----";
    let (id, _) = generate_test_keys();
    let result = decrypt_armor(invalid_armored, id.to_string().expose_secret());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        age_crypto::Error::Decrypt(age_crypto::DecryptError::InvalidCiphertext(_))
    ));
}
#[test]
fn test_decrypt_armor_invalid_identity() {
    let armored = generate_dummy_armored();
    let result = decrypt_armor(&armored, "totally invalid key");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        age_crypto::Error::Decrypt(age_crypto::DecryptError::InvalidIdentity(_))
    ));
}
#[test]
fn test_decrypt_armor_empty_armored() {
    let (id, _) = generate_test_keys();
    let result = decrypt_armor("", id.to_string().expose_secret());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        age_crypto::Error::Decrypt(age_crypto::DecryptError::InvalidCiphertext(_))
    ));
}
#[test]
fn test_decrypt_armor_corrupted_armored() {
    let (id, recipient) = generate_test_keys();
    let mut armored = encrypt_armor(b"data", &[&recipient]).unwrap().to_string();
    if armored.len() > 50 {
        armored.replace_range(40..45, "XXXXX");
    }
    let result = decrypt_armor(&armored, id.to_string().expose_secret());
    assert!(result.is_err());
}
#[test]
fn test_decrypt_armor_large_data() {
    let plaintext = vec![0xAA; 1_000_000];
    let (id, recipient) = generate_test_keys();
    let armored = encrypt_armor(&plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt_armor(armored.as_str(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_decrypt_armor_unicode() {
    let plaintext = "Decrypt 🗝️ and 中文".as_bytes();
    let (id, recipient) = generate_test_keys();
    let armored = encrypt_armor(plaintext, &[&recipient]).unwrap();
    let decrypted = decrypt_armor(armored.as_str(), id.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_decrypt_armor_multiple_recipients_any_key() {
    let plaintext = b"Shared armored secret";
    let (id1, rec1) = generate_test_keys();
    let (id2, rec2) = generate_test_keys();
    let armored = encrypt_armor(plaintext, &[&rec1, &rec2]).unwrap();
    let decrypted1 = decrypt_armor(armored.as_str(), id1.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted1, plaintext);
    let decrypted2 = decrypt_armor(armored.as_str(), id2.to_string().expose_secret()).unwrap();
    assert_eq!(decrypted2, plaintext);
}
