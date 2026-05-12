use std::io;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("No recipients provided")]
    NoRecipients,
    #[error("Invalid recipient '{recipient}': {reason}")]
    InvalidRecipient { recipient: String, reason: String },
    #[error("Encryption failed: {0}")]
    Failed(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}
impl EncryptError {
    #[must_use]
    pub fn is_user_correctable(&self) -> bool {
        matches!(
            self,
            EncryptError::NoRecipients | EncryptError::InvalidRecipient { .. }
        )
    }
    #[must_use]
    pub fn invalid_recipient(&self) -> Option<&str> {
        match self {
            EncryptError::InvalidRecipient { recipient, .. } => Some(recipient),
            _ => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, ErrorKind};
    #[test]
    fn test_no_recipients_display() {
        let err = EncryptError::NoRecipients;
        assert_eq!(format!("{}", err), "No recipients provided");
    }
    #[test]
    fn test_invalid_recipient_display() {
        let err = EncryptError::InvalidRecipient {
            recipient: "age1badkey".into(),
            reason: "invalid checksum".into(),
        };
        assert_eq!(
            format!("{}", err),
            "Invalid recipient 'age1badkey': invalid checksum"
        );
    }
    #[test]
    fn test_failed_display() {
        let err = EncryptError::Failed("internal crypto error".into());
        assert_eq!(
            format!("{}", err),
            "Encryption failed: internal crypto error"
        );
    }
    #[test]
    fn test_io_error_display() {
        let io_err = io::Error::new(ErrorKind::OutOfMemory, "alloc failed");
        let err = EncryptError::Io(io_err);
        assert_eq!(format!("{}", err), "I/O error: alloc failed");
    }
    #[test]
    fn test_from_io_error_conversion() {
        let io_err: io::Error = ErrorKind::PermissionDenied.into();
        let encrypt_err: EncryptError = io_err.into();
        assert!(matches!(encrypt_err, EncryptError::Io(_)));
    }
    #[test]
    fn test_io_error_preserves_kind() {
        let io_err = io::Error::new(ErrorKind::UnexpectedEof, "test");
        let encrypt_err = EncryptError::Io(io_err);
        if let EncryptError::Io(e) = encrypt_err {
            assert_eq!(e.kind(), ErrorKind::UnexpectedEof);
        } else {
            panic!("Expected Io variant");
        }
    }
    #[test]
    fn test_is_user_correctable_true() {
        assert!(EncryptError::NoRecipients.is_user_correctable());
        let invalid = EncryptError::InvalidRecipient {
            recipient: "bad".into(),
            reason: "x".into(),
        };
        assert!(invalid.is_user_correctable());
    }
    #[test]
    fn test_is_user_correctable_false() {
        assert!(!EncryptError::Failed("x".into()).is_user_correctable());
        assert!(!EncryptError::Io(io::Error::last_os_error()).is_user_correctable());
    }
    #[test]
    fn test_invalid_recipient_some() {
        let err = EncryptError::InvalidRecipient {
            recipient: "age1test".into(),
            reason: "bad".into(),
        };
        assert_eq!(err.invalid_recipient(), Some("age1test"));
    }
    #[test]
    fn test_invalid_recipient_none() {
        assert_eq!(EncryptError::NoRecipients.invalid_recipient(), None);
        assert_eq!(EncryptError::Failed("x".into()).invalid_recipient(), None);
    }
    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EncryptError>();
    }
    #[test]
    fn test_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<EncryptError>();
    }
    #[test]
    fn test_error_source_chain() {
        use std::error::Error as StdError;
        let io_err = io::Error::other("underlying cause");
        let encrypt_err = EncryptError::Io(io_err);
        assert!(encrypt_err.source().is_some());
    }
    #[test]
    fn test_debug_format_contains_variant_name() {
        let err = EncryptError::InvalidRecipient {
            recipient: "key".into(),
            reason: "bad".into(),
        };
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidRecipient"));
        assert!(debug.contains("key"));
    }
}
