pub mod decrypt;
pub mod encrypt;
pub use decrypt::DecryptError;
pub use encrypt::EncryptError;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum Error {
    #[error("Encrypt error: {0}")]
    Encrypt(#[from] EncryptError),
    #[error("Decrypt error: {0}")]
    Decrypt(#[from] DecryptError),
}
pub type Result<T> = std::result::Result<T, Error>;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_error_display_encrypt() {
        let err = Error::from(EncryptError::Failed("test".into()));
        assert_eq!(format!("{}", err), "Encrypt error: Encryption failed: test");
    }
    #[test]
    fn test_error_display_decrypt() {
        let err = Error::from(DecryptError::Failed("test".into()));
        assert_eq!(format!("{}", err), "Decrypt error: Decryption failed: test");
    }
    #[test]
    fn test_error_from_encrypt_error() {
        let encrypt_err = EncryptError::InvalidRecipient {
            recipient: "key".into(),
            reason: "invalid format".into(),
        };
        let err: Error = encrypt_err.into();
        assert!(matches!(
            err,
            Error::Encrypt(EncryptError::InvalidRecipient { .. })
        ));
    }
    #[test]
    fn test_error_from_decrypt_error() {
        let decrypt_err = DecryptError::InvalidIdentity("id".into());
        let err: Error = decrypt_err.into();
        assert!(matches!(
            err,
            Error::Decrypt(DecryptError::InvalidIdentity(_))
        ));
    }
}
