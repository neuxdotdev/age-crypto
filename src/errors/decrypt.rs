use std::io;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("Invalid identity: {0}")]
    InvalidIdentity(String),
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),
    #[error("Decryption failed: {0}")]
    Failed(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, ErrorKind};
    #[test]
    fn test_invalid_identity_display() {
        let err = DecryptError::InvalidIdentity("bad bech32".into());
        assert_eq!(format!("{}", err), "Invalid identity: bad bech32");
    }
    #[test]
    fn test_invalid_ciphertext_display() {
        let err = DecryptError::InvalidCiphertext("header too short".into());
        assert_eq!(format!("{}", err), "Invalid ciphertext: header too short");
    }
    #[test]
    fn test_failed_display() {
        let err = DecryptError::Failed("wrong key".into());
        assert_eq!(format!("{}", err), "Decryption failed: wrong key");
    }
    #[test]
    fn test_io_error_display() {
        let io_err = io::Error::new(ErrorKind::UnexpectedEof, "stream ended");
        let err = DecryptError::Io(io_err);
        assert_eq!(format!("{}", err), "I/O error: stream ended");
    }
    #[test]
    fn test_from_io_error_conversion() {
        let io_err: io::Error = ErrorKind::PermissionDenied.into();
        let decrypt_err: DecryptError = io_err.into();
        assert!(matches!(decrypt_err, DecryptError::Io(_)));
    }
    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DecryptError>();
    }
    #[test]
    fn test_error_source_chain() {
        use std::error::Error as StdError;
        let io_err = io::Error::other("underlying");
        let decrypt_err = DecryptError::Io(io_err);
        assert!(decrypt_err.source().is_some());
    }
}
