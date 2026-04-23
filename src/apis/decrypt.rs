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
/// ```
/// use age_crypto::decrypt;
/// use age_setup::build_keypair;
///
/// # fn main() -> age_crypto::errors::Result<()> {
/// // Generate a fresh key pair
/// let keypair = build_keypair().expect("key generation failed");
/// let pubkey = keypair.public.expose();      // "age1..."
/// let secret = keypair.secret.expose();      // "AGE-SECRET-KEY-1..."
///
/// // Encrypt a test message
/// let plaintext = b"Top secret data";
/// let encrypted = age_crypto::encrypt(plaintext, &[pubkey])?;
///
/// // Decrypt using the secret key
/// let decrypted = decrypt(encrypted.as_bytes(), secret)?;
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
