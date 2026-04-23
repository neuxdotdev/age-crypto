use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::EncryptedData;
use age::secrecy::SecretString;
use std::io::Write;

/// Encrypts plaintext using a passphrase.
///
/// Produces a binary age‑encrypted ciphertext that can be decrypted
/// with [`decrypt_with_passphrase`] using the same passphrase. No
/// key pair is required – the passphrase alone controls access to the
/// data.
///
/// Internally, the passphrase is moved into a [`SecretString`] and
/// zeroized after the scrypt identity is created. The encryption
/// process is non‑deterministic; every call with identical inputs
/// generates a distinct ciphertext due to random nonces.
///
/// # Parameters
///
/// * `plaintext` – The data to encrypt.
/// * `passphrase` – The passphrase used to protect the data.
///
/// # Returns
///
/// * `Ok(EncryptedData)` – A wrapper around the binary ciphertext.
/// * `Err(Error::Encrypt(...))` – If an internal encryption or I/O
///   failure occurs.
///
/// # Errors
///
/// | Condition                                         | Error Variant                     |
/// |---------------------------------------------------|-----------------------------------|
/// | Internal encryption failure (RNG, scrypt, etc.)   | [`EncryptError::Failed`]          |
/// | I/O error while writing the encrypted output      | [`EncryptError::Io`]              |
///
/// No `NoRecipients` or `InvalidRecipient` error is possible because
/// this function does not use recipient public keys.
///
/// # Security Considerations
///
/// * **Non‑deterministic** – repeated encryption of the same data with
///   the same passphrase yields different ciphertexts, making pattern
///   analysis harder.
/// * **Confidentiality only** – passphrase‑based encryption does not
///   authenticate the sender. If sender identity matters, use
///   key‑based encryption with X25519 identities.
/// * **Tamper‑proof** – the AEAD construction detects any modification
///   of the ciphertext.
/// * **Passphrase strength** – weak passphrases are susceptible to
///   brute‑force attacks. Use a long, high‑entropy passphrase
///   (e.g., a diceware passphrase) or a password manager.
/// * **Memory** – the passphrase is zeroized from the `SecretString`
///   as soon as the identity is created. The ciphertext is stored in
///   a standard `Vec<u8>`; consider zeroizing it after use if it
///   contains sensitive information.
///
/// # Example
///
/// ```rust
/// # fn main() -> age_crypto::errors::Result<()> {
/// let plaintext = b"Financial records";
/// let pass = "correct horse battery staple";
///
/// let encrypted = age_crypto::encrypt_with_passphrase(plaintext, pass)?;
/// assert!(!encrypted.as_bytes().is_empty());
///
/// // The same passphrase can later decrypt it
/// let decrypted = age_crypto::decrypt_with_passphrase(encrypted.as_bytes(), pass)?;
/// assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// * [`encrypt_with_passphrase_armor`] – produces PEM‑like armored output.
/// * [`encrypt`] – key‑based encryption (X25519 public keys).
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<EncryptedData> {
    let secret = SecretString::from(passphrase.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(secret);
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
