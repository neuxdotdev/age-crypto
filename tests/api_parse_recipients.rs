use age_crypto::{EncryptError, Error, encrypt};
fn valid_recipient() -> String {
    let id = age::x25519::Identity::generate();
    id.to_public().to_string()
}
#[test]
fn test_empty_recipients_error() {
    let result = encrypt(b"data", &[]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, Error::Encrypt(EncryptError::NoRecipients)));
    assert_eq!(err.to_string(), "Encrypt error: No recipients provided");
}
#[test]
fn test_invalid_recipient_not_age1_prefix() {
    let result = encrypt(b"data", &["not-an-age-key"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        Error::Encrypt(EncryptError::InvalidRecipient { .. })
    ));
    assert!(err.to_string().contains("Invalid recipient"));
}
#[test]
fn test_invalid_recipient_empty_string() {
    let result = encrypt(b"data", &[""]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        Error::Encrypt(EncryptError::InvalidRecipient { .. })
    ));
}
#[test]
fn test_invalid_recipient_random_bytes() {
    let terrible = "😱😱😱😱😱😱";
    let result = encrypt(b"data", &[terrible]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        Error::Encrypt(EncryptError::InvalidRecipient { .. })
    ));
}
#[test]
fn test_invalid_recipient_age_prefix_but_garbage() {
    let fake = "age1garbagegarbagegarbage";
    let result = encrypt(b"data", &[fake]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        Error::Encrypt(EncryptError::InvalidRecipient { .. })
    ));
}
#[test]
fn test_valid_single_recipient_success() {
    let rec = valid_recipient();
    let result = encrypt(b"data", &[&rec]);
    assert!(result.is_ok());
}
#[test]
fn test_valid_multiple_recipients_success() {
    let r1 = valid_recipient();
    let r2 = valid_recipient();
    let result = encrypt(b"data", &[&r1, &r2]);
    assert!(result.is_ok());
}
#[test]
fn test_mixed_valid_and_invalid_recipients_fails() {
    let valid = valid_recipient();
    let result = encrypt(b"data", &[&valid, "not-valid"]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Encrypt(EncryptError::InvalidRecipient { .. })
    ));
}
#[test]
fn test_duplicate_recipients_ok() {
    let rec = valid_recipient();
    let result = encrypt(b"data", &[&rec, &rec]);
    assert!(result.is_ok());
}
#[test]
fn test_unicode_recipient_fails() {
    let weird = "age1こんにちは";
    let result = encrypt(b"data", &[weird]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Encrypt(EncryptError::InvalidRecipient { .. })
    ));
}
#[test]
fn test_space_in_recipient_fails() {
    let with_space = "age1 def";
    let result = encrypt(b"data", &[with_space]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Encrypt(EncryptError::InvalidRecipient { .. })
    ));
}
