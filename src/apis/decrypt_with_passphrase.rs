use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use age::secrecy::SecretString;
use std::io::Read;

/// Decrypts ciphertext that was encrypted using a passphrase.
///
/// This function recovers the original plaintext from a binary ciphertext
/// produced by [`encrypt_with_passphrase`] (or the age CLI with `-p`).
/// It requires the same passphrase that was used for encryption.
///
/// The passphrase is immediately wrapped in a [`SecretString`], which
/// zeroizes the underlying memory on drop. The original `&str` provided
/// by the caller is left untouched; callers should manage its lifetime
/// accordingly.
///
/// # Parameters
///
/// * `ciphertext` – The encrypted age binary data.
/// * `passphrase` – The passphrase that was used to encrypt the data.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` – The decrypted plaintext bytes.
/// * `Err(Error::Decrypt(...))` – If the ciphertext is malformed, the
///   passphrase is wrong, the data has been tampered with, or an
///   internal I/O error occurs.
///
/// # Errors
///
/// | Condition                                          | Error Variant                          |
/// |----------------------------------------------------|----------------------------------------|
/// | Ciphertext is not a valid age‑encrypted stream     | [`DecryptError::InvalidCiphertext`]    |
/// | Passphrase does not match or data is tampered      | [`DecryptError::Failed`]               |
/// | I/O error during decryption (extremely rare)       | [`DecryptError::Io`]                   |
///
/// There is no `InvalidIdentity` variant because the identity is
/// derived internally from the passphrase.
///
/// # Security Considerations
///
/// * **AEAD** – age uses authenticated encryption. Any modification
///   to the ciphertext will cause decryption to fail.
/// * **scrypt KDF** – age derives a symmetric key from the passphrase
///   using scrypt, which makes brute‑force attacks computationally
///   expensive. However, weak passphrases can still be cracked.
/// * **Passphrase handling** – the passphrase is moved into a
///   `SecretString` inside the function; the original `&str` remains
///   the caller's responsibility. Avoid logging or storing the
///   passphrase unnecessarily.
/// * **Memory** – the plaintext is returned as a standard `Vec<u8>`.
///   If the plaintext is highly sensitive, consider zeroizing it after
///   use with the `zeroize` crate.
///
/// # Example
///
/// ```rust
/// # fn main() -> age_crypto::errors::Result<()> {
/// let plaintext = b"Super secret data";
/// let pass = "my-strong-passphrase";
///
/// // Encrypt first
/// let encrypted = age_crypto::encrypt_with_passphrase(plaintext, pass)?;
///
/// // Then decrypt
/// let decrypted = age_crypto::decrypt_with_passphrase(encrypted.as_bytes(), pass)?;
/// assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// * [`decrypt_with_passphrase_armor`] – armored (PEM‑like) variant.
/// * [`decrypt`] – key‑based decryption (X25519 identities).
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let secret = SecretString::from(passphrase.to_string());
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))?;
    let identity = age::scrypt::Identity::new(secret);
    let mut decrypted = Vec::new();
    decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| DecryptError::Failed(e.to_string()))?
        .read_to_end(&mut decrypted)
        .map_err(|e| DecryptError::Failed(e.to_string()))?;
    Ok(decrypted)
}
