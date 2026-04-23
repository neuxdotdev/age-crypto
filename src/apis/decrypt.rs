use crate::apis::parse_identity::parse_identity;
use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use std::io::Read;

/// Decrypts an age-encrypted ciphertext using a secret key.
///
/// # Parameters
/// - `ciphertext`: The encrypted data as a byte slice.
/// - `secret_key`: The recipient's secret key in age format (starts with `AGE-SECRET-KEY-1...`).
///
/// # Returns
/// `Ok(Vec<u8>)` with the decrypted plaintext, or an error if the key or ciphertext is invalid.
///
/// # Errors
/// | Condition | Error variant |
/// |-----------|---------------|
/// | Malformed secret key | [`DecryptError::InvalidIdentity`] |
/// | Ciphertext not valid age format | [`DecryptError::InvalidCiphertext`] |
/// | Key does not match / data tampered | [`DecryptError::Failed`] |
/// | I/O error during decryption (rare in memory) | [`DecryptError::Io`] |
///
/// # Panics
/// **No.** All errors are returned as `Err`.
///
/// # Example
/// ```rust
/// use age::x25519::Identity;
/// use age_crypto::decrypt;
/// use age::secrecy::ExposeSecret;
///
/// # fn main() -> age_crypto::errors::Result<()> {
/// // Generate a fresh key pair
/// let identity = Identity::generate();
/// let pubkey = identity.to_public();
/// let secret_key = identity.to_string();  // Returns SecretBox<str>
///
/// // Encrypt a test message
/// let plaintext = b"Top secret data";
/// let encrypted = age_crypto::encrypt(plaintext, &[&pubkey.to_string()])?;
///
/// // Decrypt: use .expose_secret() to get &str from SecretBox<str>
/// let decrypted = decrypt(encrypted.as_bytes(), secret_key.expose_secret())?;
/// assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// ```
pub fn decrypt(ciphertext: &[u8], secret_key: &str) -> Result<Vec<u8>> {
    let identity = parse_identity(secret_key)?;
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))?;
    let mut decrypted = Vec::new();
    decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| DecryptError::Failed(e.to_string()))?
        .read_to_end(&mut decrypted)
        .map_err(|e| DecryptError::Failed(e.to_string()))?;
    Ok(decrypted)
}
