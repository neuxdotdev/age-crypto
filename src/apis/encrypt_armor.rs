//! Key‑based encryption to armored (PEM‑like) age ciphertexts.

use crate::apis::parse_recipients::parse_recipients;
use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::ArmoredData;
use age::armor::{ArmoredWriter, Format};
use std::io::Write;

/// Encrypts plaintext for one or more recipients and returns the result
/// in **armor‑encoded** (PEM‑like) format.
///
/// # Overview
///
/// This function is the armored counterpart to [`encrypt`]. Instead of
/// returning raw binary ciphertext, it wraps the encrypted data in a
/// `-----BEGIN AGE ENCRYPTED FILE-----` / `-----END AGE ENCRYPTED FILE-----`
/// envelope, making it safe to transmit over text‑based channels (email,
/// chat, JSON, etc.).
///
/// The returned [`ArmoredData`] guarantees that the string:
/// - is valid UTF‑8,
/// - contains the standard age armor markers,
/// - can be passed directly to [`decrypt_armor`].
///
/// # Parameters
///
/// - `plaintext`: The data to encrypt, as a byte slice.
/// - `recipients`: A slice of recipient public keys, each a string
///   starting with `age1...`. At least one recipient is required.
///
/// # Returns
///
/// - `Ok(ArmoredData)` – a newtype wrapping the armored ciphertext.
/// - `Err(Error::Encrypt(...))` – if any step fails (see [Errors](#errors)).
///
/// # Errors
///
/// | Condition | Error Variant |
/// |-----------|---------------|
/// | `recipients` is empty | [`EncryptError::NoRecipients`] |
/// | Any recipient string is not a valid age public key | [`EncryptError::InvalidRecipient`] |
/// | Internal encryption failure (RNG, key wrapping) | [`EncryptError::Failed`] |
/// | I/O error while writing the armored output | [`EncryptError::Io`] |
/// | The armor output is not valid UTF‑8 (should never happen) | [`EncryptError::Failed`] (with a descriptive message) |
///
/// # Panics
///
/// **No.** The function never panics; all error conditions are returned as `Err`.
///
/// # Security Notes
///
/// - Non‑deterministic – each call produces a different ciphertext,
///   even for the same plaintext and recipients.
/// - Multi‑recipient – any single recipient whose public key was
///   included can decrypt the result (using the corresponding secret key).
/// - Tamper‑evident – the armor+encryption combination is
///   authenticated; modifying a single character of the armored text
///   will make decryption fail.
/// - Armor suitability – the output is safe to embed in JSON,
///   XML, or email bodies because it uses only printable ASCII
///   characters and fixed‑width lines.
/// - Memory – the entire armored string is built in memory. For
///   very large files (>100 MB), consider streaming the encryption
///   directly with `age::Encryptor` and `ArmoredWriter`.
///
/// # Example
///
/// ```
/// use age_crypto::encrypt_armor;
/// use age_setup::build_keypair;
///
/// # fn main() -> age_crypto::errors::Result<()> {
/// // Generate two key pairs
/// let alice = build_keypair().expect("key generation failed");
/// let bob   = build_keypair().expect("key generation failed");
/// let pub_a = alice.public.expose();
/// let pub_b = bob.public.expose();
///
/// // Encrypt for both recipients
/// let plaintext = b"Multi\xE2\x80\x91recipient secret";
/// let armored = encrypt_armor(plaintext, &[pub_a, pub_b])?;
///
/// // Verify the armor markers
/// assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
/// assert!(armored.ends_with("-----END AGE ENCRYPTED FILE-----\n"));
/// // or simply use the built-in check
/// assert!(age_crypto::ArmoredData::is_valid_armored(&armored));
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`encrypt`] – binary (non‑armored) encryption.
/// - [`encrypt_with_passphrase_armor`] – passphrase‑based armored encryption.
pub fn encrypt_armor(plaintext: &[u8], recipients: &[&str]) -> Result<ArmoredData> {
    let recipient_list = parse_recipients(recipients)?;
    let encryptor =
        age::Encryptor::with_recipients(recipient_list.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| EncryptError::Failed(e.to_string()))?;
    let mut armored = Vec::new();
    let mut writer = ArmoredWriter::wrap_output(&mut armored, Format::AsciiArmor)
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    let mut inner = encryptor
        .wrap_output(&mut writer)
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    inner
        .write_all(plaintext)
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    inner
        .finish()
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    let pem = String::from_utf8(armored)
        .map_err(|e| EncryptError::Failed(format!("Armor output not UTF-8: {}", e)))?;
    Ok(ArmoredData::new(pem))
}
