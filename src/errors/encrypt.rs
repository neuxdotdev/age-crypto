use std::io;
use thiserror::Error;

/// Errors that can happen during **encryption** operations.
///
/// # Overview
///
/// `EncryptError` enumerates every failure path specific to encryption:
/// invalid recipient keys, missing recipients, internal encryption
/// failures, and I/O glitches. It is the symmetric counterpart to
/// [`DecryptError`] and follows the same design principles:
///
/// - **Fine‑grained** – callers can distinguish between "no recipients"
///   and "invalid recipient X" and act accordingly (e.g., ask the user
///   to provide a correct key).
/// - **Context‑rich** – the error variants carry the problematic data
///   (`recipient` field) and a `reason` string, so error messages are
///   self‑contained and helpful.
/// - **Ergonomic** – automatic `From` conversions mean minimal
///   boilerplate inside the encryption functions.
///
/// All public encryption APIs return `crate::errors::Result<T>`, where
/// `crate::errors::Error` can hold an `EncryptError` via the `#[from]`
/// conversion.
///
/// # Example: Basic error handling with public API
///
/// ```rust
/// use age_crypto::{encrypt_with_passphrase, Error};
///
/// let plaintext = b"Secret message";
/// let passphrase = "my-strong-passphrase";
///
/// match encrypt_with_passphrase(plaintext, passphrase) {
///     Ok(encrypted) => {
///         println!("Encrypted {} bytes", encrypted.as_bytes().len());
///     }
///     Err(Error::Encrypt(e)) => {
///         eprintln!("Encryption error: {}", e);
///     }
///     Err(e) => {
///         eprintln!("Unexpected error: {}", e);
///     }
/// }
/// ```
///
/// # Example: Distinguishing specific error variants
///
/// ```rust
/// use age_crypto::{encrypt_with_passphrase, Error};
/// use age_crypto::errors::EncryptError;
///
/// // Contoh: mencoba encrypt dengan passphrase kosong (mungkin gagal tergantung implementasi)
/// let result = encrypt_with_passphrase(b"test", "");
///
/// if let Err(Error::Encrypt(err)) = result {
///     match err {
///         EncryptError::NoRecipients => {
///             // Variant ini lebih relevan untuk key-based encryption
///             eprintln!("No recipients specified");
///         }
///         EncryptError::InvalidRecipient { recipient, reason } => {
///             eprintln!("Recipient '{}' is invalid: {}", recipient, reason);
///         }
///         EncryptError::Failed(msg) => {
///             eprintln!("Encryption failed internally: {}", msg);
///         }
///         EncryptError::Io(e) => {
///             eprintln!("I/O error during encryption: {}", e);
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
pub enum EncryptError {
    /// The list of recipients is empty.
    ///
    /// Age encryption requires at least one valid public key so that the
    /// resulting ciphertext can be decrypted by the corresponding private
    /// key. This error is returned immediately from the
    /// `parse_recipients` helper when an empty slice is provided, before
    /// any cryptographic work is done.
    ///
    /// **Why not just encrypt to "no one"?**  
    /// That would produce a ciphertext that cannot be decrypted, which is
    /// almost certainly a mistake. By treating this as an error, we force
    /// the caller to consciously provide a recipient.
    ///
    /// # Example scenario
    ///
    /// ```rust
    /// use age_crypto::errors::EncryptError;
    ///
    /// fn validate_recipients(recips: &[String]) -> Result<(), EncryptError> {
    ///     if recips.is_empty() {
    ///         return Err(EncryptError::NoRecipients);
    ///     }
    ///     Ok(())
    /// }
    ///
    /// // Usage:
    /// assert!(validate_recipients(&[]).is_err());
    /// assert!(validate_recipients(&["age1valid...".into()]).is_ok());
    /// ```
    #[error("No recipients provided")]
    NoRecipients,

    /// A specific recipient string could not be parsed as a valid X25519
    /// public key.
    ///
    /// Age public keys normally look like `age1...` followed by a Bech32
    /// string. This variant is returned when `x25519::Recipient::from_str`
    /// fails. The fields are:
    ///
    /// - `recipient`: the original string that failed to parse.
    /// - `reason`: the parser's error description (e.g., "invalid bech32",
    ///   "bad checksum", "unsupported version").
    ///
    /// By including the offending string, the caller can report exactly
    /// which recipient was problematic without needing to copy it into
    /// the error themselves.
    ///
    /// # Example: Parsing validation
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use age::x25519::Recipient;
    /// use age_crypto::errors::EncryptError;
    ///
    /// # fn example() -> Result<(), EncryptError> {
    /// let key = "age1-invalid-key-format";
    ///
    /// // Attempt to parse; on failure, convert to our error type
    /// Recipient::from_str(key)
    ///     .map_err(|e| EncryptError::InvalidRecipient {
    ///         recipient: key.to_string(),
    ///         reason: format!("Parse error: {}", e),
    ///     })?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Example: Error output format
    ///
    /// ```text
    /// recipients = ["age1valid", "not-a-key", "age1another"]
    /// -> EncryptError::InvalidRecipient {
    ///        recipient: "not-a-key",
    ///        reason: "invalid bech32 checksum"
    ///    }
    /// -> Display: "Invalid recipient 'not-a-key': invalid bech32 checksum"
    /// ```
    #[error("Invalid recipient '{recipient}': {reason}")]
    InvalidRecipient {
        /// The original string that was supposed to be an age public key.
        recipient: String,
        /// The explanation from the parser about why it is invalid.
        reason: String,
    },

    /// The encryption process encountered an internal error.
    ///
    /// This variant covers all age‑internal failures that are not related
    /// to recipient parsing or I/O. For example:
    ///
    /// - Failure to generate a shared secret from a recipient's key.
    /// - Failure to wrap the symmetric key.
    /// - Unexpected errors from the random number generator.
    ///
    /// The inner [`String`] contains whatever error message the `age`
    /// crate produced. While this is not as structured as the other
    /// variants, it ensures no error is silently swallowed.
    ///
    /// # When this occurs
    ///
    /// This error is relatively rare in practice because the `age` crate
    /// is well-tested. Common triggers include:
    ///
    /// - Memory allocation failures during cryptographic operations
    /// - Unexpected state in the encryption state machine
    /// - Platform-specific cryptographic backend issues
    ///
    /// # Debugging tip
    ///
    /// If you encounter this error frequently, consider:
    ///
    /// 1. Updating the `age` and `age-crypto` crates to latest versions
    /// 2. Checking system resources (memory, entropy pool)
    /// 3. Reporting the issue with the full error message for investigation
    #[error("Encryption failed: {0}")]
    Failed(String),

    /// An I/O error occurred while writing the encrypted output.
    ///
    /// Even though our API writes into a `Vec<u8>`, the `Encryptor` uses
    /// a generic `Write` implementation. In extremely rare circumstances
    /// (e.g., out‑of‑memory), writing to the vector may yield an
    /// [`io::Error`].
    ///
    /// Because this variant is annotated with `#[from] io::Error`, any
    /// `?` on an I/O operation inside an encryption function will
    /// automatically promote the `io::Error` into `EncryptError::Io`.
    ///
    /// # Example of automatic I/O error conversion
    ///
    /// ```rust
    /// use std::io::Write;
    /// use age_crypto::errors::EncryptError;
    ///
    /// fn write_encrypted<W: Write>(
    ///     writer: &mut W,
    ///     plaintext: &[u8]
    /// ) -> Result<(), EncryptError> {
    ///     // Any io::Error from write_all is automatically converted
    ///     // to EncryptError::Io via the `?` operator
    ///     writer.write_all(plaintext)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Common I/O error scenarios
    ///
    /// | ErrorKind | Likely cause |
    /// |-----------|-------------|
    /// | `WriteZero` | Writer returned 0 bytes written (unusual for Vec) |
    /// | `OutOfMemory` | System ran out of memory during allocation |
    /// | `Interrupted` | Operation interrupted by signal (rare in memory ops) |
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

// ============================================================================
// 🔧 HELPER METHODS (optional but useful for error inspection)
// ============================================================================
impl EncryptError {
    /// Returns `true` if this error indicates a user-correctable issue
    /// (e.g., invalid recipient format) rather than an internal failure.
    ///
    /// This can help decide whether to prompt the user to retry with
    /// different input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use age_crypto::errors::EncryptError;
    ///
    /// let err = EncryptError::InvalidRecipient {
    ///     recipient: "bad-key".into(),
    ///     reason: "invalid bech32".into(),
    /// };
    ///
    /// if err.is_user_correctable() {
    ///     println!("Please check your recipient key and try again.");
    /// }
    /// ```
    #[must_use]
    pub fn is_user_correctable(&self) -> bool {
        matches!(
            self,
            EncryptError::NoRecipients | EncryptError::InvalidRecipient { .. }
        )
    }

    /// Returns the problematic recipient string if this is an
    /// `InvalidRecipient` error, or `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use age_crypto::errors::EncryptError;
    ///
    /// let err = EncryptError::InvalidRecipient {
    ///     recipient: "age1bad...".into(),
    ///     reason: "checksum failed".into(),
    /// };
    ///
    /// if let Some(bad_key) = err.invalid_recipient() {
    ///     eprintln!("The key '{}' is invalid", bad_key);
    /// }
    /// ```
    #[must_use]
    pub fn invalid_recipient(&self) -> Option<&str> {
        match self {
            EncryptError::InvalidRecipient { recipient, .. } => Some(recipient),
            _ => None,
        }
    }
}

// ============================================================================
// 🧪 UNIT TESTS (comprehensive coverage for EncryptError)
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, ErrorKind};

    // ────────────────────────────────────────────────────────────────
    // Display trait tests
    // ────────────────────────────────────────────────────────────────
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

    // ────────────────────────────────────────────────────────────────
    // From<io::Error> conversion tests
    // ────────────────────────────────────────────────────────────────
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

    // ────────────────────────────────────────────────────────────────
    // Helper method tests
    // ────────────────────────────────────────────────────────────────
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

    // ────────────────────────────────────────────────────────────────
    // Type safety & trait tests
    // ────────────────────────────────────────────────────────────────
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

        let io_err = io::Error::new(ErrorKind::Other, "underlying cause");
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
