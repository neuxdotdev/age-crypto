use age_crypto::{
    ArmoredData, Error, decrypt_with_passphrase_armor, encrypt_with_passphrase_armor,
};
use std::collections::HashSet;
const PASSPHRASE: &str = "correct-horse-battery-staple-🔐";
#[test]
fn test_encrypt_passphrase_armor_success() {
    let plaintext = b"Hello, armored password world!";
    let result = encrypt_with_passphrase_armor(plaintext, PASSPHRASE);
    assert!(result.is_ok());
    let armored = result.unwrap();
    assert!(!armored.is_empty());
    assert!(ArmoredData::is_valid_armored(armored.as_str()));
    assert!(
        armored
            .as_str()
            .starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
    );
    assert!(
        armored
            .as_str()
            .ends_with("-----END AGE ENCRYPTED FILE-----\n")
    );
}
#[test]
fn test_encrypt_passphrase_armor_roundtrip() {
    let plaintexts: Vec<&[u8]> = vec![
        b"",
        b"x",
        b"Hello, World!",
        "🔐 Unicode 中文 🗝️".as_bytes(),
        &[0u8; 1000],
        &[255u8; 5000],
    ];
    for pt in plaintexts {
        let armored = encrypt_with_passphrase_armor(pt, PASSPHRASE).unwrap();
        let decrypted = decrypt_with_passphrase_armor(armored.as_str(), PASSPHRASE).unwrap();
        assert_eq!(decrypted, pt);
    }
}
#[test]
fn test_encrypt_passphrase_armor_different_passphrases_differ() {
    let pt = b"Same plaintext";
    let armored1 = encrypt_with_passphrase_armor(pt, "pass-one").unwrap();
    let armored2 = encrypt_with_passphrase_armor(pt, "pass-two").unwrap();
    assert_ne!(armored1.as_str(), armored2.as_str());
    assert!(decrypt_with_passphrase_armor(armored1.as_str(), "pass-two").is_err());
    assert!(decrypt_with_passphrase_armor(armored2.as_str(), "pass-one").is_err());
}
#[test]
fn test_encrypt_passphrase_armor_randomized_output() {
    let pt = b"Randomized?";
    let mut seen = HashSet::new();
    for _ in 0..5 {
        let armored = encrypt_with_passphrase_armor(pt, PASSPHRASE).unwrap();
        let s = armored.to_string();
        assert!(seen.insert(s), "Armored output must be unique per call");
    }
}
#[test]
fn test_encrypt_passphrase_armor_empty_plaintext() {
    let armored = encrypt_with_passphrase_armor(b"", PASSPHRASE).unwrap();
    let decrypted = decrypt_with_passphrase_armor(armored.as_str(), PASSPHRASE).unwrap();
    assert_eq!(decrypted, b"");
}
#[test]
fn test_encrypt_passphrase_armor_large_plaintext() {
    let plaintext = vec![0x5A; 1_000_000];
    let armored = encrypt_with_passphrase_armor(&plaintext, PASSPHRASE).unwrap();
    let decrypted = decrypt_with_passphrase_armor(armored.as_str(), PASSPHRASE).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_encrypt_passphrase_armor_unicode_passphrase_and_text() {
    let pass = "パスワード 密码 🗝️";
    let plaintext = "こんにちは 世界".as_bytes();
    let armored = encrypt_with_passphrase_armor(plaintext, pass).unwrap();
    let decrypted = decrypt_with_passphrase_armor(armored.as_str(), pass).unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_encrypt_passphrase_armor_tampered_armor_fails() {
    let pt = b"Tamper test";
    let mut armored = encrypt_with_passphrase_armor(pt, PASSPHRASE)
        .unwrap()
        .to_string();
    armored.replace_range(50..51, "X");
    let result = decrypt_with_passphrase_armor(&armored, PASSPHRASE);
    assert!(
        result.is_err(),
        "Tampered armored data should fail decryption"
    );
}
#[test]
fn test_encrypt_passphrase_armor_truncated_armor_fails() {
    let pt = b"Truncation test";
    let armored = encrypt_with_passphrase_armor(pt, PASSPHRASE).unwrap();
    let truncated = &armored.as_str()[..50];
    let result = decrypt_with_passphrase_armor(truncated, PASSPHRASE);
    assert!(result.is_err());
}
#[test]
fn test_encrypt_passphrase_armor_invalid_armor_format_fails() {
    let result = decrypt_with_passphrase_armor("not-an-age-armor", PASSPHRASE);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Decrypt(age_crypto::DecryptError::InvalidCiphertext(_))
    ));
}
#[test]
fn test_encrypt_passphrase_armor_error_propagation() {
    let armored = encrypt_with_passphrase_armor(b"data", PASSPHRASE).unwrap();
    let err = decrypt_with_passphrase_armor(armored.as_str(), "oops").unwrap_err();
    assert!(matches!(
        err,
        Error::Decrypt(age_crypto::DecryptError::Failed(_))
    ));
}
