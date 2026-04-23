use age_crypto::{
    DecryptError, Error, decrypt_with_passphrase_armor, encrypt_with_passphrase_armor,
};
const CORRECT_PHRASE: &str = "correct-horse-battery-staple-🔐";
const WRONG_PHRASE: &str = "wrong-passphrase-❌";
fn create_armored_ciphertext(plaintext: &[u8], passphrase: &str) -> String {
    encrypt_with_passphrase_armor(plaintext, passphrase)
        .expect("encryption for test setup failed")
        .to_string()
}
#[test]
fn test_decrypt_passphrase_armor_success() {
    let plaintext = b"Top secret armored";
    let armored = create_armored_ciphertext(plaintext, CORRECT_PHRASE);
    let decrypted = decrypt_with_passphrase_armor(&armored, CORRECT_PHRASE).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_decrypt_passphrase_armor_wrong_passphrase() {
    let armored = create_armored_ciphertext(b"secret", CORRECT_PHRASE);
    let result = decrypt_with_passphrase_armor(&armored, WRONG_PHRASE);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, Error::Decrypt(DecryptError::Failed(_))));
    assert!(
        err.to_string().contains("Decrypt error: Decryption failed")
            || err.to_string().contains("no matching secret key")
    );
}
#[test]
fn test_decrypt_passphrase_armor_empty_string() {
    let result = decrypt_with_passphrase_armor("", CORRECT_PHRASE);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Decrypt(DecryptError::InvalidCiphertext(_))
    ));
}
#[test]
fn test_decrypt_passphrase_armor_invalid_marker() {
    let invalid = "-----BEGIN WRONG-----\n...\n-----END WRONG-----";
    let result = decrypt_with_passphrase_armor(invalid, CORRECT_PHRASE);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Decrypt(DecryptError::InvalidCiphertext(_))
    ));
}
#[test]
fn test_decrypt_passphrase_armor_truncated() {
    let full = create_armored_ciphertext(b"data", CORRECT_PHRASE);
    for len in [0, 20, full.len() / 2, full.len() - 1] {
        if len < full.len() {
            let truncated = &full[..len];
            let result = decrypt_with_passphrase_armor(truncated, CORRECT_PHRASE);
            assert!(result.is_err(), "Truncated at {} must fail", len);
        }
    }
}
#[test]
fn test_decrypt_passphrase_armor_corrupted() {
    let mut full = create_armored_ciphertext(b"I am data", CORRECT_PHRASE);
    let pos = full.len() / 2;
    let bytes = unsafe { full.as_bytes_mut() };
    bytes[pos] ^= 0xFF;
    let result = decrypt_with_passphrase_armor(&full, CORRECT_PHRASE);
    assert!(result.is_err());
}
#[test]
fn test_decrypt_passphrase_armor_case_sensitive_passphrase() {
    let armored = create_armored_ciphertext(b"case test", "MyPass");
    assert!(decrypt_with_passphrase_armor(&armored, "MyPass").is_ok());
    assert!(decrypt_with_passphrase_armor(&armored, "mypass").is_err());
    assert!(decrypt_with_passphrase_armor(&armored, "MYPASS").is_err());
}
#[test]
fn test_decrypt_passphrase_armor_unicode_passphrase() {
    let pass = "パスワード 密码 🗝️";
    let plaintext = b"Unicode armored";
    let armored = encrypt_with_passphrase_armor(plaintext, pass).unwrap();
    let decrypted = decrypt_with_passphrase_armor(armored.as_str(), pass).unwrap();
    assert_eq!(decrypted, plaintext);
    let mut wrong = pass.to_string();
    wrong.push('x');
    assert!(decrypt_with_passphrase_armor(armored.as_str(), &wrong).is_err());
}
#[test]
fn test_decrypt_passphrase_armor_large_ciphertext() {
    let plaintext = vec![0xCD; 500_000];
    let armored = encrypt_with_passphrase_armor(&plaintext, CORRECT_PHRASE).unwrap();
    let decrypted = decrypt_with_passphrase_armor(armored.as_str(), CORRECT_PHRASE).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_decrypt_passphrase_armor_reuse() {
    let plaintext = b"Immortal";
    let armored = create_armored_ciphertext(plaintext, CORRECT_PHRASE);
    for _ in 0..5 {
        let decrypted = decrypt_with_passphrase_armor(&armored, CORRECT_PHRASE).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
#[test]
fn test_decrypt_passphrase_armor_output_fresh_allocation() {
    let armored = create_armored_ciphertext(b"fresh", CORRECT_PHRASE);
    let d1 = decrypt_with_passphrase_armor(&armored, CORRECT_PHRASE).unwrap();
    let d2 = decrypt_with_passphrase_armor(&armored, CORRECT_PHRASE).unwrap();
    assert_ne!(d1.as_ptr(), d2.as_ptr(), "Outputs must be independent");
    assert_eq!(d1, d2);
}
#[test]
fn test_decrypt_passphrase_armor_does_not_mutate_input() {
    let armored = create_armored_ciphertext(b"immutable", CORRECT_PHRASE);
    let original = armored.clone();
    let _ = decrypt_with_passphrase_armor(&armored, CORRECT_PHRASE).unwrap();
    assert_eq!(
        armored, original,
        "Input armored string must not be mutated"
    );
}
