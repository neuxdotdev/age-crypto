//! Passphrase‑based decryption of binary age ciphertexts.

use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use age::armor::ArmoredReader;
use age::secrecy::SecretString;
use std::io::Read;

/// Decrypts an **armor‑encoded** age ciphertext that was encrypted with a
/// passphrase.
///
/// This function is the armored counterpart to
/// [`decrypt_with_passphrase`]. It accepts a PEM‑like string (the kind
/// produced by `age -p -a` or [`encrypt_with_passphrase_armor`]) together
/// with the correct passphrase, and returns the original plaintext.
///
/// Internally, the passphrase is moved into a [`SecretString`] and used to
/// derive an scrypt identity. The armored wrapper is stripped by an
/// [`ArmoredReader`], after which decryption proceeds exactly like the
/// binary passphrase path.
///
/// # Parameters
///
/// * `armored` – The complete armored age ciphertext, including the
///   `-----BEGIN AGE ENCRYPTED FILE-----` and `-----END AGE ENCRYPTED FILE-----`
///   markers.
/// * `passphrase` – The passphrase that was used to encrypt the data.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` – The decrypted plaintext bytes.
/// * `Err(Error::Decrypt(...))` – If the armored data is malformed, the
///   passphrase is wrong, the data has been tampered with, or an internal
///   I/O error occurs.
///
/// # Errors
///
/// | Condition                                                   | Error Variant                          |
/// |-------------------------------------------------------------|----------------------------------------|
/// | Armored text does not contain a valid age ciphertext        | [`DecryptError::InvalidCiphertext`]    |
/// | Passphrase does not match or data has been tampered         | [`DecryptError::Failed`]               |
/// | I/O error while reading the armored stream (extremely rare) | [`DecryptError::Io`]                   |
///
/// # Security Considerations
///
/// * **AEAD** – The underlying age encryption is authenticated. Any
///   modification to the armored text (including whitespace) will cause
///   decryption to fail.
/// * **scrypt KDF** – The passphrase is used to derive a symmetric key
///   via scrypt, which makes brute‑force attacks computationally
///   expensive. However, weak passphrases remain vulnerable – always use
///   a long, high‑entropy passphrase.
/// * **Passphrase handling** – The passphrase is immediately moved into
///   a `SecretString` and zeroized after use. The caller’s original
///   `&str` is left untouched; avoid logging or persisting it.
/// * **Armor is not encryption** – The armor encoding adds no extra
///   secrecy; it simply encodes the ciphertext in a text‑safe format.
/// * **Memory** – The entire plaintext is returned as a single `Vec<u8>`.
///   For very large files, consider streaming decryption directly with the
///   `age` crate to avoid high memory usage.
///
/// # Example
///
/// ```rust
/// # fn main() -> age_crypto::errors::Result<()> {
/// let plaintext = b"Confidential message";
/// let pass = "correct horse battery staple";
///
/// // Encrypt with armor
/// let armored = age_crypto::encrypt_with_passphrase_armor(plaintext, pass)?;
/// assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
///
/// // Decrypt the armored output
/// let decrypted = age_crypto::decrypt_with_passphrase_armor(&armored, pass)?;
/// assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// * [`decrypt_with_passphrase`] – binary (non‑armored) variant.
/// * [`decrypt_armor`] – key‑based armored decryption.
/// * [`encrypt_with_passphrase_armor`] – the encryption counterpart.
pub fn decrypt_with_passphrase_armor(armored: &str, passphrase: &str) -> Result<Vec<u8>> {
    let secret = SecretString::from(passphrase.to_string());
    let reader = ArmoredReader::new(armored.as_bytes());
    let decryptor =
        age::Decryptor::new(reader).map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))?;
    let identity = age::scrypt::Identity::new(secret);
    let mut decrypted = Vec::new();
    decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| DecryptError::Failed(e.to_string()))?
        .read_to_end(&mut decrypted)
        .map_err(|e| DecryptError::Failed(e.to_string()))?;
    Ok(decrypted)
}
