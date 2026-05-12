use age_crypto::errors::DecryptError;
use std::error::Error;
use std::io;
#[test]
fn test_decrypt_error_invalid_identity_display() {
    let err = DecryptError::InvalidIdentity("bad key format".to_string());
    assert_eq!(err.to_string(), "Invalid identity: bad key format");
}
#[test]
fn test_decrypt_error_invalid_identity_debug() {
    let err = DecryptError::InvalidIdentity("bad key format".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("InvalidIdentity"));
    assert!(debug_str.contains("bad key format"));
}
#[test]
fn test_decrypt_error_invalid_identity_source() {
    let err = DecryptError::InvalidIdentity("msg".to_string());
    assert!(err.source().is_none());
}
#[test]
fn test_decrypt_error_invalid_ciphertext_display() {
    let err = DecryptError::InvalidCiphertext("corrupted data".to_string());
    assert_eq!(err.to_string(), "Invalid ciphertext: corrupted data");
}
#[test]
fn test_decrypt_error_invalid_ciphertext_debug() {
    let err = DecryptError::InvalidCiphertext("corrupted data".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("InvalidCiphertext"));
    assert!(debug_str.contains("corrupted data"));
}
#[test]
fn test_decrypt_error_invalid_ciphertext_source() {
    let err = DecryptError::InvalidCiphertext("msg".to_string());
    assert!(err.source().is_none());
}
#[test]
fn test_decrypt_error_failed_display() {
    let err = DecryptError::Failed("decryption failed".to_string());
    assert_eq!(err.to_string(), "Decryption failed: decryption failed");
}
#[test]
fn test_decrypt_error_failed_debug() {
    let err = DecryptError::Failed("decryption failed".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("Failed"));
    assert!(debug_str.contains("decryption failed"));
}
#[test]
fn test_decrypt_error_failed_source() {
    let err = DecryptError::Failed("msg".to_string());
    assert!(err.source().is_none());
}
#[test]
fn test_decrypt_error_io_display() {
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
    let err = DecryptError::Io(io_err);
    assert_eq!(err.to_string(), "I/O error: access denied");
}
#[test]
fn test_decrypt_error_io_debug() {
    let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
    let err = DecryptError::Io(io_err);
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("Io"));
    assert!(debug_str.contains("NotFound"));
}
#[test]
fn test_decrypt_error_io_source() {
    let io_err = io::Error::other("custom io error");
    let err = DecryptError::Io(io_err);
    let source = err.source();
    assert!(source.is_some());
    assert_eq!(source.unwrap().to_string(), "custom io error");
}
#[test]
fn test_decrypt_error_from_io_conversion() {
    let io_err = io::Error::new(io::ErrorKind::WriteZero, "write zero");
    let err: DecryptError = io_err.into();
    match err {
        DecryptError::Io(e) => {
            assert_eq!(e.kind(), io::ErrorKind::WriteZero);
            assert_eq!(e.to_string(), "write zero");
        }
        _ => panic!("Expected Io variant"),
    }
}
#[test]
fn test_decrypt_error_from_io_display() {
    let io_err = io::Error::new(io::ErrorKind::Interrupted, "interrupted");
    let err = DecryptError::from(io_err);
    assert_eq!(err.to_string(), "I/O error: interrupted");
}
#[test]
fn test_decrypt_error_into_boxed_error() {
    let err = DecryptError::Failed("fail".to_string());
    let boxed: Box<dyn Error> = Box::new(err);
    assert_eq!(boxed.to_string(), "Decryption failed: fail");
}
