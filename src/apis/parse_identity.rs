use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use std::str::FromStr;

/// Parses a secret key string into an [`age::x25519::Identity`].
///
/// This **crate‑internal** helper is used by every key‑based decryption
/// function ([`decrypt`](super::decrypt),
/// [`decrypt_armor`](super::decrypt_armor)). It wraps the `age`
/// library’s `Identity::from_str`, converting any parse error into a
/// concrete [`DecryptError::InvalidIdentity`] variant that is `Send`
/// and `Sync`.
///
/// # Parameters
///
/// * `secret_key` – A string slice containing an age secret key,
///   typically starting with `AGE-SECRET-KEY-1...`.
///
/// # Returns
///
/// * `Ok(age::x25519::Identity)` – The parsed identity, ready for
///   decryption.
/// * `Err(Error::Decrypt(...))` – If the string is not a valid age
///   identity. The error variant `InvalidIdentity` is automatically
///   promoted to the crate‑level `Error` when used with `?`.
///
/// # Errors
///
/// | Condition                                     | Error Variant                                                          |
/// |-----------------------------------------------|------------------------------------------------------------------------|
/// | `secret_key` is malformed or unparsable       | [`DecryptError::InvalidIdentity`] containing a descriptive message     |
///
/// # Panics
///
/// **None.** The function always returns a `Result`.
///
/// # Design Rationale
///
/// The `age` crate returns `Box<dyn Error>` from parsing. We convert it
/// to a `String` to ensure our error type remains concrete, `Send`, and
/// `Sync`, which simplifies error handling in async contexts and
/// multi‑threaded environments. The original error text is preserved
/// verbatim.
///
/// # Usage (crate‑internal)
///
/// ```ignore
/// // Inside decrypt() or decrypt_armor()
/// let identity = parse_identity(secret_key)?;
/// let decryptor = age::Decryptor::new(ciphertext)?;
/// // ...
/// ```
pub(crate) fn parse_identity(secret_key: &str) -> Result<age::x25519::Identity> {
    age::x25519::Identity::from_str(secret_key)
        .map_err(|e| DecryptError::InvalidIdentity(format!("Parse failed: {}", e)).into())
}
