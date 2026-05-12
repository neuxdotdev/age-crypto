use age_crypto::errors::EncryptError;
use std::error::Error;
use std::io;
#[test]
fn test_encrypt_error_no_recipients_display() {
    let err = EncryptError::NoRecipients;
    assert_eq!(err.to_string(), "No recipients provided");
}
#[test]
fn test_encrypt_error_no_recipients_debug() {
    let err = EncryptError::NoRecipients;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("NoRecipients"));
}
#[test]
fn test_encrypt_error_no_recipients_source() {
    let err = EncryptError::NoRecipients;
    assert!(err.source().is_none());
}
#[test]
fn test_encrypt_error_invalid_recipient_display() {
    let err = EncryptError::InvalidRecipient {
        recipient: "abc123".to_string(),
        reason: "invalid x25519 key".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "Invalid recipient 'abc123': invalid x25519 key"
    );
}
#[test]
fn test_encrypt_error_invalid_recipient_debug() {
    let err = EncryptError::InvalidRecipient {
        recipient: "abc123".to_string(),
        reason: "invalid x25519 key".to_string(),
    };
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("InvalidRecipient"));
    assert!(debug_str.contains("abc123"));
    assert!(debug_str.contains("invalid x25519 key"));
}
#[test]
fn test_encrypt_error_invalid_recipient_source() {
    let err = EncryptError::InvalidRecipient {
        recipient: "abc123".to_string(),
        reason: "invalid x25519 key".to_string(),
    };
    assert!(err.source().is_none());
}
#[test]
fn test_encrypt_error_failed_display() {
    let err = EncryptError::Failed("something went wrong".to_string());
    assert_eq!(err.to_string(), "Encryption failed: something went wrong");
}
#[test]
fn test_encrypt_error_failed_debug() {
    let err = EncryptError::Failed("something went wrong".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("Failed"));
    assert!(debug_str.contains("something went wrong"));
}
#[test]
fn test_encrypt_error_failed_source() {
    let err = EncryptError::Failed("msg".to_string());
    assert!(err.source().is_none());
}
#[test]
fn test_encrypt_error_io_display() {
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
    let err = EncryptError::Io(io_err);
    assert_eq!(err.to_string(), "I/O error: denied");
}
#[test]
fn test_encrypt_error_io_debug() {
    let io_err = io::Error::new(io::ErrorKind::NotFound, "missing");
    let err = EncryptError::Io(io_err);
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("Io"));
    assert!(debug_str.contains("NotFound"));
}
#[test]
fn test_encrypt_error_io_source() {
    let io_err = io::Error::other("underlying");
    let err = EncryptError::Io(io_err);
    let source = err.source();
    assert!(source.is_some());
    assert_eq!(source.unwrap().to_string(), "custom");
}
#[test]
fn test_encrypt_error_from_io_conversion() {
    let io_err = io::Error::new(io::ErrorKind::WriteZero, "write zero");
    let err: EncryptError = io_err.into();
    match err {
        EncryptError::Io(e) => {
            assert_eq!(e.kind(), io::ErrorKind::WriteZero);
            assert_eq!(e.to_string(), "write zero");
        }
        _ => panic!("Expected Io variant"),
    }
}
#[test]
fn test_encrypt_error_from_io_display() {
    let io_err = io::Error::new(io::ErrorKind::Interrupted, "interrupted");
    let err = EncryptError::from(io_err);
    assert_eq!(err.to_string(), "I/O error: interrupted");
}
#[test]
fn test_encrypt_error_into_boxed_error() {
    let err = EncryptError::Failed("fail".to_string());
    let boxed: Box<dyn Error> = Box::new(err);
    assert_eq!(boxed.to_string(), "Encryption failed: fail");
}
