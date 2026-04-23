//! # Error handling for the `age_crypto` library
//!
//! This module defines the unified error type and the alias `Result` used
//! across the entire library. It re‑exports the sub‑module errors so that
//! users can conveniently match on specific failure reasons if they wish.
//!
//! # Structure
//!
//! ```text
//! errors
//! ├── decrypt.rs  → DecryptError (four variants for decrypt-specific failures)
//! ├── encrypt.rs  → EncryptError (four variants for encrypt-specific failures)
//! └── mod.rs      → Error (top-level enum), Result type alias
//! ```
//!
//! The top‑level [`Error`] is an enum with two variants:
//! - `Error::Encrypt(EncryptError)`
//! - `Error::Decrypt(DecryptError)`
//!
//! Both variants are created automatically from their respective
//! sub‑errors thanks to the `#[from]` attribute. This means:
//!
//! 1. Functions that work internally with `DecryptError` (e.g., the
//!    `parse_identity` helper) can return `DecryptError` without worrying
//!    about the outer type.
//! 2. The public API functions (e.g., `crate::decrypt`) have a return type
//!    of `Result<T>` (i.e., `std::result::Result<T, Error>`). When they
//!    use `?` on an expression that returns `Result<_, DecryptError>`, the
//!    conversion to `Error::Decrypt` happens automatically.
//!
//! # Usage for library consumers
//!
//! ## Basic error handling
//!
//! ```rust
//! use age_crypto::{decrypt_with_passphrase, Error};
//!
//! // Contoh: ciphertext dummy untuk demonstrasi
//! let ciphertext = b"AGE-ENC..."; // hasil dari encrypt_with_passphrase
//! let passphrase = "my-secret-pass";
//!
//! match decrypt_with_passphrase(ciphertext, passphrase) {
//!     Ok(plaintext) => println!("Decrypted: {:?}", std::str::from_utf8(&plaintext)),
//!     Err(Error::Decrypt(e)) => eprintln!("Decrypt error: {}", e),
//!     Err(Error::Encrypt(e)) => eprintln!("Unexpected encrypt error: {}", e),
//! }
//! ```
//!
//! ## Distinguishing error kinds
//!
//! ```rust
//! use age_crypto::{decrypt_with_passphrase, Error};
//! use age_crypto::errors::DecryptError;
//!
//! let ciphertext = b"invalid-ciphertext";
//! let passphrase = "wrong-pass";
//!
//! match decrypt_with_passphrase(ciphertext, passphrase) {
//!     Ok(plain) => {
//!         // Handle successful decryption
//!         let _ = plain;
//!     }
//!     Err(Error::Decrypt(DecryptError::InvalidCiphertext(_))) => {
//!         // Handle corrupted or malformed ciphertext
//!         eprintln!("Ciphertext is invalid or corrupted");
//!     }
//!     Err(Error::Decrypt(DecryptError::Failed(_))) => {
//!         // Handle wrong passphrase or authentication failure
//!         eprintln!("Wrong passphrase or integrity check failed");
//!     }
//!     Err(Error::Decrypt(DecryptError::Io(e))) => {
//!         // Handle I/O errors during decryption
//!         eprintln!("I/O error: {}", e);
//!     }
//!     Err(other) => eprintln!("Unexpected error: {}", other),
//! }
//! ```
//!
//! # Why two‑level error design?
//!
//! - **Separation of concerns**: Encryption and decryption are distinct
//!   operations with different failure modes. Keeping them in separate
//!   enums makes the code self‑documenting.
//! - **Extensibility**: In the future, we could add a `ConfigError` or
//!   `KeyGenerationError` variant to the top‑level `Error` without
//!   touching the encrypt/decrypt types.
//! - **Backward compatibility**: Adding a new variant to a public enum is
//!   a breaking change. With the two‑level approach, we can sometimes
//!   add variants to `DecryptError` without directly breaking the top‑level
//!   `Error` ABI (though it still breaks exhaustive matches on
//!   `DecryptError`). The outer `Error` remains stable as long as we
//!   don't add a new variant there.

pub mod decrypt;
pub mod encrypt;

pub use decrypt::DecryptError;
pub use encrypt::EncryptError;

use thiserror::Error;

/// The universal error type for this crate.
///
/// This enum represents every possible error that a function in this
/// library can return. It is a thin wrapper around the domain‑specific
/// error types:
///
/// - [`EncryptError`] for encryption‑related failures.
/// - [`DecryptError`] for decryption‑related failures.
///
/// The `#[from]` attribute generates `From<EncryptError>` and
/// `From<DecryptError>` implementations, so conversions are automatic
/// (see [module documentation](self) for details). This keeps the
/// public API clean – all functions return a single error type, yet
/// callers can still inspect the underlying cause.
///
/// # Display format
///
/// Each variant prefixes the error message with the domain:
///
/// ```text
/// Encrypt error: Invalid recipient 'abc': reason
/// Decrypt error: Invalid identity: something
/// ```
///
/// # Example of error propagation with `?`
///
/// ```rust
/// use age_crypto::{encrypt_with_passphrase, Error};
///
/// fn safe_encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, Error> {
///     // encrypt_with_passphrase already returns Result<_, Error>
///     // so we can use `?` directly for propagation
///     let encrypted = encrypt_with_passphrase(plaintext, passphrase)?;
///     Ok(encrypted.as_bytes().to_vec())
/// }
/// ```
#[derive(Debug, Error)]
pub enum Error {
    /// An encryption‑related error occurred.
    ///
    /// The inner [`EncryptError`] provides detailed information about
    /// missing recipients, invalid keys, or internal failures.
    #[error("Encrypt error: {0}")]
    Encrypt(#[from] EncryptError),

    /// A decryption‑related error occurred.
    ///
    /// The inner [`DecryptError`] provides detailed information about
    /// invalid identities, broken ciphertext, or decryption mismatches.
    #[error("Decrypt error: {0}")]
    Decrypt(#[from] DecryptError),
}

/// Convenient alias for `std::result::Result<T, crate::errors::Error>`.
///
/// All public API functions that can fail use this type. By importing
/// `crate::errors::Result`, you can write:
///
/// ```rust
/// use age_crypto::errors::Result;
///
/// fn my_function() -> Result<String> {
///     // Return Ok with a value
///     Ok(String::from("success"))
/// }
/// ```
///
/// without needing to specify `Error` explicitly. The type is re‑exported
/// from the crate root, so `age_crypto::Result` is also available.
///
/// # Example with error propagation
///
/// ```rust
/// use age_crypto::{encrypt_with_passphrase, errors::Result};
///
/// fn process_and_encrypt(data: &str, pass: &str) -> Result<Vec<u8>> {
///     // Any error from encrypt_with_passphrase is automatically
///     // converted to our crate::errors::Error via the `?` operator
///     let encrypted = encrypt_with_passphrase(data.as_bytes(), pass)?;
///     Ok(encrypted.as_bytes().to_vec())
/// }
/// ```
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
