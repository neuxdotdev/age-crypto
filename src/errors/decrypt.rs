//! Decryption‑specific error types.

use std::io;
use thiserror::Error;

/// Errors that can occur during **decryption** operations.
///
/// # Overview
///
/// This enum represents every possible failure mode that the decryption
/// functions may encounter. It is designed to be:
///
/// - **Specific** – each variant describes a distinct category of failure.
/// - **Informative** – the attached data (strings, etc.) provide precise
///   diagnostics, so callers can either display an error message or
///   programmatically react (e.g., retry with a different identity).
/// - **Composable** – it implements [`std::error::Error`] and can be
///   seamlessly converted into the crate‑level [`Error`](super::Error)
///   (which further wraps both encryption and decryption errors).
///
/// The enum is derived with [`thiserror::Error`], which automatically
/// implements `Display` and `Error` based on the `#[error("...")]`
/// attributes. This avoids boilerplate while keeping the error messages
/// clear and greppable.
///
/// # Where it appears
///
/// Every public decryption API (e.g., [`crate::decrypt_with_passphrase`],
/// [`crate::decrypt_with_passphrase_armor`]) returns
/// `crate::errors::Result<T>`, which under the hood is
/// `std::result::Result<T, crate::errors::Error>`.  
/// The crate‑level [`Error`](super::Error) has a variant `Decrypt` that
/// automatically converts from `DecryptError` via `#[from]`. Thus, when a
/// decryption helper fails with a `DecryptError`, the `?` operator promotes
/// it to the top‑level error type without manual `.map_err(...)`.
///
/// # Example: Basic error handling
///
/// ```rust
/// use age_crypto::{decrypt_with_passphrase, Error};
///
/// let ciphertext = b"AGE-ENC..."; // dummy ciphertext for demo
/// let passphrase = "my-secret";
///
/// match decrypt_with_passphrase(ciphertext, passphrase) {
///     Ok(plaintext) => println!("Success: {} bytes", plaintext.len()),
///     Err(Error::Decrypt(e)) => eprintln!("Decrypt error: {}", e),
///     Err(e) => eprintln!("Unexpected error: {}", e),
/// }
/// ```
///
/// # Example: Distinguishing error variants
///
/// ```rust
/// use age_crypto::{decrypt_with_passphrase, Error};
/// use age_crypto::errors::DecryptError;
///
/// let bad_ct = b"not-valid-age-data";
/// let result = decrypt_with_passphrase(bad_ct, "any-pass");
///
/// if let Err(Error::Decrypt(err)) = result {
///     match err {
///         DecryptError::InvalidCiphertext(_) => {
///             eprintln!("Ciphertext is malformed or corrupted");
///         }
///         DecryptError::Failed(_) => {
///             eprintln!("Wrong passphrase or integrity check failed");
///         }
///         DecryptError::Io(e) => {
///             eprintln!("I/O error during decryption: {}", e);
///         }
///         DecryptError::InvalidIdentity(_) => {
///             // This variant is more relevant for key-based decryption
///             eprintln!("Identity parsing issue");
///         }
///     }
/// }
/// ```
///
/// # Error handling philosophy
///
/// - **No panics** – all error paths return a `Result`; the library never
///   aborts due to invalid input.
/// - **Transparent wrapping** – underlying library errors (from the `age`
///   crate) are stringified with `.to_string()` so that the error chain
///   remains meaningful even if the inner error type is not exposed.
/// - **I/O errors are propagated automatically** – see [`Io`] variant.
#[derive(Debug, Error)]
pub enum DecryptError {
    /// The identity (secret key) provided is malformed or cannot be parsed.
    ///
    /// Decryption requires a valid `age` identity, typically an
    /// `AGE-SECRET-KEY-1...` string (X25519 identity). This variant is
    /// returned when `age::x25519::Identity::from_str` fails. The inner
    /// [`String`] contains the parser's error message, e.g.:
    ///
    /// * "invalid bech32 checksum"
    /// * "unknown version"
    /// * "unexpected length"
    ///
    /// **Why not just return the raw parse error?**  
    /// The `age` crate does not expose a structured error type for parsing;
    /// it returns a `Box<dyn std::error::Error>`. We stringify it so that
    /// our error type remains concrete, `Send + Sync`, and easy to display.
    ///
    /// # Example scenario
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use age::x25519::Identity;
    /// use age_crypto::errors::DecryptError;
    ///
    /// # fn example() -> Result<(), DecryptError> {
    /// let key = "AGE-SECRET-KEY-INVALID-EXAMPLE";
    /// let identity = Identity::from_str(key)
    ///     .map_err(|e| DecryptError::InvalidIdentity(format!("Parse error: {}", e)))?;
    /// # Ok(())
    /// # }
    /// ```
    #[error("Invalid identity: {0}")]
    InvalidIdentity(String),

    /// The ciphertext (encrypted data) is not a valid age-encrypted stream.
    ///
    /// This error occurs when `age::Decryptor::new` fails to parse the
    /// beginning of the ciphertext. The age format starts with a version
    /// tag and contains header records; if that structure is corrupted,
    /// truncated, or simply not an age file, this variant is returned.
    ///
    /// The string contains the exact reason from the `age` crate, which
    /// can help developers distinguish between:
    ///
    /// * "header is too short" (truncated file)
    /// * "unknown version" (future or incompatible format)
    /// * MAC verification failure at the header level
    ///
    /// **Important:** This error is raised *before* any decryption attempt.
    /// It signals a structural problem, not a wrong key.
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Decryption itself failed — the identity is not suitable for this
    /// ciphertext, or the data is corrupted beyond simple format errors.
    ///
    /// This is a catch‑all for when the decryptor is successfully
    /// constructed but the actual key exchange or symmetric decryption
    /// fails. Reasons include:
    ///
    /// * No recipient stanza matches the provided identity
    ///   (e.g., you encrypted to Alice's key but provided Bob's identity).
    /// * HMAC verification fails (tampered ciphertext).
    /// * A scrypt passphrase-based identity is wrong.
    ///
    /// The inner [`String`] contains the lower‑level error description
    /// from `age`.
    ///
    /// **Design note:** In a later version, we might split this into more
    /// specific variants (e.g., `WrongKey`, `TamperedData`), but for now
    /// a single `Failed` keeps the API simple while still providing the
    /// error message.
    #[error("Decryption failed: {0}")]
    Failed(String),

    /// An I/O error occurred while reading or writing during decryption.
    ///
    /// Even though our high‑level API operates entirely in memory (using
    /// `Vec<u8>` or `&[u8]`), the underlying `age` library works with
    /// generic `Read`/`Write` traits. Therefore, it can theoretically
    /// produce an [`io::Error`] (e.g., if the in‑memory stream encounters
    /// an allocation failure, though rare).
    ///
    /// This variant implements `From<io::Error>` via the `#[from]`
    /// attribute, which means you can use the `?` operator directly
    /// on any I/O operation inside a function that returns
    /// `Result<_, DecryptError>`. The conversion is lossless – the
    /// original `io::Error` is stored inside and can be recovered.
    ///
    /// # Example of automatic I/O error conversion
    ///
    /// ```rust
    /// use std::io::Read;
    /// use age_crypto::errors::DecryptError;
    ///
    /// fn read_all<R: Read>(stream: &mut R) -> Result<Vec<u8>, DecryptError> {
    ///     let mut buf = Vec::new();
    ///     // io::Error is automatically converted to DecryptError::Io via `?`
    ///     stream.read_to_end(&mut buf)?;
    ///     Ok(buf)
    /// }
    /// ```
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

// ============================================================================
// UNIT TESTS (for DecryptError itself)
// ============================================================================
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
        let io_err = io::Error::new(ErrorKind::Other, "underlying");
        let decrypt_err = DecryptError::Io(io_err);
        assert!(decrypt_err.source().is_some());
    }
}
