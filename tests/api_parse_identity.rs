use age::secrecy::ExposeSecret;
use age_crypto::{DecryptError, Error, decrypt, encrypt};
fn generate_keypair() -> (age::x25519::Identity, String) {
    let id = age::x25519::Identity::generate();
    let pubkey = id.to_public().to_string();
    (id, pubkey)
}
fn generate_ciphertext(pubkey: &str) -> Vec<u8> {
    encrypt(b"test plaintext", &[pubkey]).unwrap().to_vec()
}
#[test]
fn test_valid_identity_success() {
    let (id, pubkey) = generate_keypair();
    let ct = generate_ciphertext(&pubkey);
    let result = decrypt(&ct, id.to_string().expose_secret());
    assert!(result.is_ok());
}
#[test]
fn test_invalid_identity_malformed_string() {
    let (_, pubkey) = generate_keypair();
    let ct = generate_ciphertext(&pubkey);
    let result = decrypt(&ct, "not-a-valid-age-secret-key");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        Error::Decrypt(DecryptError::InvalidIdentity(_))
    ));
    assert!(err.to_string().contains("Invalid identity"));
}
#[test]
fn test_invalid_identity_empty_string() {
    let (_, pubkey) = generate_keypair();
    let ct = generate_ciphertext(&pubkey);
    let result = decrypt(&ct, "");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Decrypt(DecryptError::InvalidIdentity(_))
    ));
}
#[test]
fn test_invalid_identity_wrong_format_but_valid_prefix() {
    let (_, pubkey) = generate_keypair();
    let ct = generate_ciphertext(&pubkey);
    let bad_key = "AGE-SECRET-KEY-1GARBAGE";
    let result = decrypt(&ct, bad_key);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Decrypt(DecryptError::InvalidIdentity(_))
    ));
}
#[test]
fn test_valid_format_but_wrong_secret_key_gives_failed_not_invalid_identity() {
    let (wrong_id, _) = generate_keypair();
    let (_, pubkey) = generate_keypair();
    let ct = generate_ciphertext(&pubkey);
    let result = decrypt(&ct, wrong_id.to_string().expose_secret());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::Decrypt(DecryptError::Failed(_))),
        "Expected DecryptError::Failed, got {:?}",
        err
    );
}
#[test]
fn test_null_byte_in_identity_fails_parsing() {
    let (_, pubkey) = generate_keypair();
    let ct = generate_ciphertext(&pubkey);
    let bad = "AGE-SECRET-KEY-1\0more";
    let err = decrypt(&ct, bad).unwrap_err();
    assert!(
        matches!(err, Error::Decrypt(DecryptError::InvalidIdentity(_)))
            || matches!(err, Error::Decrypt(DecryptError::InvalidCiphertext(_)))
    );
}
