use crate::apis::parse_recipients::parse_recipients;
use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::EncryptedData;
use std::io::Write;

/// Encrypts plaintext for one or more recipients using age.
///
/// # Parameters
/// - `plaintext`: Data to encrypt.
/// - `recipients`: Slice of recipient public keys (each starts with `age1...`).
///
/// # Returns
/// `Ok(EncryptedData)` containing the encrypted bytes.
///
/// # Errors
/// | Condition | Error variant |
/// |-----------|---------------|
/// | Empty recipient list | [`EncryptError::NoRecipients`] |
/// | Invalid recipient string | [`EncryptError::InvalidRecipient`] |
/// | Internal encryption failure | [`EncryptError::Failed`] |
/// | I/O error during writing | [`EncryptError::Io`] |
///
/// # Panics
/// **No.** All failure paths are handled gracefully.
///
/// # Example
/// ```rust
/// use age::x25519::Identity;
/// use age_crypto::encrypt;
///
/// # fn main() -> age_crypto::errors::Result<()> {
/// // Create two identities
/// let alice = Identity::generate();
/// let bob = Identity::generate();
///
/// // Convert public keys to String, then get &str references
/// let alice_pub = alice.to_public().to_string();
/// let bob_pub = bob.to_public().to_string();
/// let recipients = [alice_pub.as_str(), bob_pub.as_str()];  // [&str; 2]
///
/// // Use &str (not byte string) to avoid ASCII-only limitation
/// let data = "Multi-recipient secret";
/// let encrypted = encrypt(data.as_bytes(), &recipients)?;
///
/// assert!(!encrypted.as_bytes().is_empty());
/// # Ok(())
/// # }
/// ```
///
pub fn encrypt(plaintext: &[u8], recipients: &[&str]) -> Result<EncryptedData> {
    let recipient_list = parse_recipients(recipients)?;
    let encryptor =
        age::Encryptor::with_recipients(recipient_list.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| EncryptError::Failed(e.to_string()))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    Ok(EncryptedData::new(encrypted))
}
