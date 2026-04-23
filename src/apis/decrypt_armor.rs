use crate::apis::parse_identity::parse_identity;
use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use age::armor::ArmoredReader;
use std::io::Read;

/// Decrypts an **armor‑encoded** age ciphertext using a secret key.
///
/// # Overview
///
/// This function is the armored counterpart to [`decrypt`]. It takes a
/// PEM‑like string (with `-----BEGIN AGE ENCRYPTED FILE-----` markers)
/// and a secret key, and returns the original plaintext.
///
/// The armored format is defined by the age specification and is
/// identical to the output of the official CLI tool when using the `-a`
/// flag.
///
/// # Parameters
///
/// - `armored`: A string slice containing the complete armored age
///   ciphertext, including `BEGIN` and `END` lines.
/// - `secret_key`: The recipient’s secret key in age format
///   (`AGE-SECRET-KEY-1...`).
///
/// # Returns
///
/// - `Ok(Vec<u8>)` – the decrypted plaintext bytes.
/// - `Err(Error::Decrypt(...))` – if any step fails (see [Errors](#errors)).
///
/// # Errors
///
/// | Condition | Error Variant |
/// |-----------|---------------|
/// | `secret_key` is malformed or not a valid X25519 identity | [`DecryptError::InvalidIdentity`] |
/// | The armored string does not contain a valid age ciphertext | [`DecryptError::InvalidCiphertext`] |
/// | The key does not match the ciphertext or data is tampered | [`DecryptError::Failed`] |
/// | An I/O error occurs while reading the armored stream (extremely rare) | [`DecryptError::Io`] |
///
/// All error variants are automatically converted to the crate‑level
/// [`Error`](crate::errors::Error) by the `?` operator, so callers can
/// match on the outer `Error` or on the inner `DecryptError` as needed.
///
/// # Panics
///
/// **No.** This function never panics; every failure is returned as
/// `Err`.
///
/// # Security Notes
///
/// -  Authenticated Encryption – any modification to the armored
///   text will cause decryption to fail.
/// - Armor is not encryption – the armor is only a base64
///   encoding; the cryptographic security comes from the age ciphertext
///   embedded within.
/// - Memory – the entire plaintext is loaded into a `Vec<u8>`.
///   For very large files, consider streaming the decryption using the
///   underlying `age` API directly.
/// - Secret key exposure – the `secret_key` is used only for
///   identity derivation; it is not stored or logged. However, callers
///   should still treat the key string as sensitive and avoid
///   unnecessary copies.
///
/// # Example
///
/// ```
/// use age_crypto::decrypt_armor;
/// use age_setup::build_keypair;
///
/// # fn main() -> age_crypto::errors::Result<()> {
/// // Generate a key pair
/// let keypair = build_keypair().expect("key generation failed");
/// let pubkey = keypair.public.expose();    // "age1..."
/// let secret = keypair.secret.expose();    // "AGE-SECRET-KEY-1..."
///
/// // Encrypt some data into armored form
/// let plaintext = b"Confidential document";
/// let armored = age_crypto::encrypt_armor(plaintext, &[pubkey])?;
///
/// // Decrypt the armor using the secret key
/// let decrypted = decrypt_armor(&armored, secret)?;
/// assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`decrypt`] – decryption of binary (non‑armored) ciphertext.
/// - [`decrypt_with_passphrase_armor`] – passphrase‑based armored decryption.
pub fn decrypt_armor(armored: &str, secret_key: &str) -> Result<Vec<u8>> {
    let identity = parse_identity(secret_key)?;
    let reader = ArmoredReader::new(armored.as_bytes());
    let decryptor =
        age::Decryptor::new(reader).map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))?;
    let mut decrypted = Vec::new();
    decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| DecryptError::Failed(e.to_string()))?
        .read_to_end(&mut decrypted)
        .map_err(|e| DecryptError::Failed(e.to_string()))?;
    Ok(decrypted)
}
