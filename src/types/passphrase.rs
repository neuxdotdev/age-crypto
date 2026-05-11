//! Passphrase type with secure memory handling.
//!
//! This module provides the [`Passphrase`] type, which wraps a secret string
//! (passphrase) and ensures it is zeroized from memory when dropped. It also
//! redacts the passphrase in debug and display outputs to prevent accidental
//! exposure.

use std::fmt;
use zeroize::Zeroize;

/// A passphrase for password‑based encryption and decryption.
///
/// # Purpose
///
/// `Passphrase` wraps a secret string (the passphrase) and ensures that it is:
/// - **Erased from memory** when no longer needed (via a custom [`Drop`]).
/// - **Redacted** in debug and display output to prevent accidental exposure.
///
/// This follows the principle of least privilege for secrets: the plaintext
/// passphrase lives in memory for the shortest possible time and is never
/// accidentally logged.
///
/// # Construction
///
/// Use [`Passphrase::new`] to create an instance from a `&str`. The
/// constructor copies the bytes into a heap‑allocated buffer (`Vec<u8>`)
/// that we control.
///
/// # Accessing the passphrase
///
/// The only way to access the contents is [`expose`](Passphrase::expose),
/// which returns a `&str`. This method is intentionally named `expose` to
/// make it obvious that you are revealing the secret.
///
/// # Memory clearing
///
/// When a `Passphrase` is dropped, the [`Drop`] implementation:
/// 1. Writes `0` to every byte of the internal buffer using
///    [`std::ptr::write_volatile`] to prevent the compiler from optimizing
///    away the write (it is not a “dead store”).
/// 2. Emits a **sequential consistency memory fence** via
///    [`std::sync::atomic::fence`] to ensure the zeroing is visible to
///    all threads and not reordered.
///
/// This makes it much harder for an attacker with access to memory dumps
/// to recover the passphrase after the `Passphrase` has been dropped.
///
/// # Cloning
///
/// `Passphrase` implements [`Clone`]. Cloning creates a **new copy** of
/// the secret in memory. Both the original and the clone will be zeroed
/// independently when they are dropped. Avoid unnecessary cloning to
/// reduce the number of copies of the secret in memory.
///
/// # Examples
///
/// ```ignore
/// use age_crypto::types::Passphrase;
///
/// let pass = Passphrase::new("my-secret-password");
/// let plaintext = pass.expose(); // use for encryption/decryption
/// assert_eq!(plaintext, "my-secret-password");
/// // pass is dropped here → memory zeroed
/// ```
pub struct Passphrase {
    inner: Vec<u8>,
}

impl Passphrase {
    /// Creates a new `Passphrase` from a string slice.
    ///
    /// The passphrase is copied into an internally managed buffer. The
    /// original string slice remains untouched; you should take care to
    /// also clear or avoid storing the original if it is sensitive (e.g.,
    /// using `secrecy::SecretString` at the call site).
    ///
    /// # Panics
    ///
    /// This function does not panic. The input must be valid UTF‑8 because
    /// it is already a `&str`, and we simply store its bytes.
    pub fn new(passphrase: &str) -> Self {
        Self {
            inner: passphrase.as_bytes().to_vec(),
        }
    }

    /// Returns the secret passphrase as a string slice.
    ///
    /// This is the **only** way to access the secret. The method is called
    /// `expose` to serve as a deliberate signal: every time you call it,
    /// you extend the lifetime of the secret in plaintext.
    ///
    /// # Panics
    ///
    /// In theory, if the internal bytes were somehow corrupted into invalid
    /// UTF‑8, this method would panic. However, the only way to create a
    /// `Passphrase` is through [`new`](Passphrase::new), which always
    /// stores valid UTF‑8 bytes, so this panic is impossible in practice.
    #[must_use]
    pub fn expose(&self) -> &str {
        // Safety: `new` always initializes from a valid &str
        std::str::from_utf8(&self.inner).expect("Passphrase must be valid UTF-8")
    }

    /// Returns the number of bytes (not characters) of the passphrase.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the passphrase is empty.
    ///
    /// An empty passphrase is generally a bad idea for encryption, but
    /// this method is provided for completeness.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// **Security‑critical drop implementation.**
///
/// When a `Passphrase` goes out of scope, its byte buffer is overwritten
/// with zeros to reduce the window of memory exposure. The use of
/// `write_volatile` and a memory fence helps ensure the clearing is not
/// optimized away by the compiler and is visible to all execution threads.
///
/// # Important
///
/// - This does **not** scrub other copies of the passphrase that may exist
///   in strings or other buffers. The caller is responsible for managing
///   those.
/// - The clearing happens *before* deallocation, but after zeroing the
///   memory is still part of the allocation and could theoretically be
///   swapped to disk or read by another process with sufficient privileges.
///   For the highest security, use [`secrecy::SecretVec`] or similar
///   dedicated types.
impl Drop for Passphrase {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Cloning a `Passphrase` duplicates the secret into a new buffer.
///
/// Both the clone and the original will be independently zeroed when
/// dropped. Be mindful that this increases the number of copies of the
/// secret in memory; clone only when absolutely necessary.
impl Clone for Passphrase {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Debug formatting that **never** reveals the passphrase.
///
/// The output shows only the length of the passphrase and a `[REDACTED]`
/// placeholder. This makes it safe to include `Passphrase` in structs
/// that derive `Debug` without accidentally logging the secret.
impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passphrase")
            .field("len", &self.inner.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Display that **never** reveals the passphrase.
///
/// Any attempt to format a `Passphrase` with `{}` will produce the
/// constant string `[REDACTED]`. This prevents accidental exposure in
/// user‑facing messages or logs.
impl fmt::Display for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}
