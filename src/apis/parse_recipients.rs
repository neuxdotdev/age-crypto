use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use age::x25519;
use std::str::FromStr;

/// Validates and parses a list of recipient strings into a vector of
/// [`x25519::Recipient`]s.
///
/// This **crate‑internal** utility is used by every public key‑based
/// encryption function ([`encrypt`](super::encrypt),
/// [`encrypt_armor`](super::encrypt_armor)). It enforces two critical
/// invariants:
///
/// 1. At least one recipient must be provided.
/// 2. Every string must be a well‑formed age public key (`age1...`).
///
/// # Parameters
///
/// * `recipients` – A slice of string slices, each expected to be an
///   age public key in Bech32 encoding.
///
/// # Returns
///
/// * `Ok(Vec<x25519::Recipient>)` – The parsed recipient objects, ready
///   for use with [`age::Encryptor::with_recipients`].
/// * `Err(Error::Encrypt(...))` – If the list is empty or any recipient
///   fails to parse. The conversion from `EncryptError` to the
///   crate‑level `Error` is automatic via the `?` operator.
///
/// # Errors
///
/// | Condition                                                       | Error Variant                                                                 |
/// |-----------------------------------------------------------------|-------------------------------------------------------------------------------|
/// | `recipients` is empty                                           | [`EncryptError::NoRecipients`]                                                |
/// | Any string is not a valid X25519 public key                     | [`EncryptError::InvalidRecipient`] with the offending string and parse reason |
///
/// # Panics
///
/// **None.** The function returns `Err` for invalid input; it never panics.
///
/// # Implementation Notes
///
/// * Parsing is delegated to `x25519::Recipient::from_str`, which
///   verifies the Bech32 encoding and key version.
/// * Error messages from the `age` crate are captured with
///   `.to_string()` to keep our own error type concrete, `Send`, and
///   `Sync` while preserving the full diagnostic.
/// * The returned vector pre‑allocates exactly the needed capacity to
///   avoid re‑allocations.
///
/// # Usage (crate‑internal)
///
/// ```ignore
/// // Inside encrypt() or encrypt_armor()
/// let recipient_list = parse_recipients(&["age1...", "age1..."])?;
/// let encryptor = age::Encryptor::with_recipients(
///     recipient_list.iter().map(|r| r as &dyn age::Recipient)
/// )?;
/// ```
pub(crate) fn parse_recipients(recipients: &[&str]) -> Result<Vec<x25519::Recipient>> {
    if recipients.is_empty() {
        return Err(EncryptError::NoRecipients.into());
    }
    let mut list = Vec::with_capacity(recipients.len());
    for r in recipients {
        let recipient =
            x25519::Recipient::from_str(r).map_err(|e| EncryptError::InvalidRecipient {
                recipient: r.to_string(),
                reason: e.to_string(),
            })?;
        list.push(recipient);
    }
    Ok(list)
}
