//! Binary age ciphertext type.
//!
//! This module provides the [`EncryptedData`] type, a wrapper around `Vec<u8>`
//! representing raw binary age encrypted data. This is the compact, non‑text
//! output format of age encryption.

use std::fmt;

/// A newtype over [`Vec<u8>`] representing **binary** (non‑armored) age
/// encrypted data.
///
/// # Overview
///
/// This is the raw, binary output of age encryption when no armor is
/// requested. It is the complement of [`ArmoredData`]. The inner bytes are
/// the direct result of the `age::Encryptor` writer — a compact, but not
/// human‑readable, ciphertext.
///
/// # Why wrap a `Vec<u8>`?
///
/// Exactly the same reasons as `ArmoredData`:
/// - **Type distinctness** – prevents mixing up plaintext, encrypted data,
///   and other byte buffers at the type level.
/// - **Controlled construction** – `new` is `pub(crate)`, so only the
///   encryption functions can create an `EncryptedData`. This guarantees
///   that any `EncryptedData` you hold came from a successful encryption
///   operation.
/// - **Ergonomics** – implements [`AsRef<[u8]>`], `From` conversions, and
///   provides accessor methods. The [`Display`] implementation shows only
///   the byte length to avoid dumping binary data to the screen.
///
/// # Examples
///
/// ```ignore
/// use age_crypto::encrypt;
///
/// let encrypted: EncryptedData = encrypt(b"secret", &["age1..."]).unwrap();
/// println!("{}", encrypted);          // [EncryptedData: 512 bytes]
/// let raw: &[u8] = encrypted.as_bytes();
/// let owned: Vec<u8> = encrypted.to_vec();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData(Vec<u8>);

impl EncryptedData {
    /// Creates a new `EncryptedData` from raw binary ciphertext.
    ///
    /// This is `pub(crate)` because it must only be called after a
    /// successful encryption. The value is taken as‑is; no further
    /// validation is needed because the `age` library already produced
    /// a well‑formed ciphertext.
    #[must_use]
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Returns the binary ciphertext as a byte slice.
    ///
    /// This provides read‑only access to the encrypted bytes. Use it when
    /// you need to write the data to a file or network stream.
    ///
    /// # Example
    ///
    /// ```ignore
    /// std::fs::write("data.age", encrypted.as_bytes())?;
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Converts the ciphertext into an owned [`Vec<u8>`].
    ///
    /// This clones the internal buffer. If you need to take ownership
    /// without cloning, use [`From<EncryptedData> for Vec<u8>`] instead,
    /// which consumes the `EncryptedData`.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Returns the number of bytes in the ciphertext.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the ciphertext is empty.
    ///
    /// Note: a valid age encrypted stream is never truly empty because it
    /// always contains at least a header. However, this method is provided
    /// for consistency.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

/// Allows `&EncryptedData` to be used wherever `&[u8]` is expected.
///
/// This means you can pass an `EncryptedData` directly to functions that
/// take a byte slice, such as `write_all` or `copy_to`.
impl AsRef<[u8]> for EncryptedData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Converts an owned [`Vec<u8>`] into an `EncryptedData`.
///
/// **Caution:** No validation is performed. The caller must guarantee
/// that the bytes constitute a valid age binary ciphertext. In normal
/// use, only the encryption functions should use this conversion.
impl From<Vec<u8>> for EncryptedData {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

/// Extracts the raw byte vector from the wrapper.
///
/// This consumes the `EncryptedData`, giving you full ownership of the
/// underlying [`Vec<u8>`] without cloning.
impl From<EncryptedData> for Vec<u8> {
    fn from(data: EncryptedData) -> Self {
        data.0
    }
}

/// Displays a description showing the byte length only.
///
/// Printing raw binary data is seldom useful and could clutter output
/// or accidentally expose ciphertext. The `Display` implementation
/// limits itself to a short, human‑readable summary.
impl fmt::Display for EncryptedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[EncryptedData: {} bytes]", self.0.len())
    }
}
