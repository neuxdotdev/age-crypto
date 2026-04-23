use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::ArmoredData;
use age::armor::{ArmoredWriter, Format};
use age::secrecy::SecretString;
use std::io::Write;

/// Encrypts plaintext with a passphrase and returns the result in
/// **armor‑encoded** (PEM‑like) format.
///
/// This function is the armored counterpart to
/// [`encrypt_with_passphrase`]. It encrypts the given data using the
/// supplied passphrase and wraps the binary ciphertext inside an age‑armor
/// envelope (`-----BEGIN AGE ENCRYPTED FILE-----` ...
/// `-----END AGE ENCRYPTED FILE-----`).
///
/// The returned [`ArmoredData`] is guaranteed to be valid UTF‑8 and
/// contain the standard armor markers, making it safe for text‑based
/// transport (email, JSON, configuration files, etc.).
///
/// # Parameters
///
/// * `plaintext` – The data to encrypt.
/// * `passphrase` – The passphrase used to protect the data.
///
/// # Returns
///
/// * `Ok(ArmoredData)` – A wrapper around the armored ciphertext.
/// * `Err(Error::Encrypt(...))` – If encryption, armor writing, or UTF‑8
///   conversion fails.
///
/// # Errors
///
/// | Condition                                                 | Error Variant                     |
/// |-----------------------------------------------------------|-----------------------------------|
/// | Internal encryption failure (RNG, scrypt)                 | [`EncryptError::Failed`]          |
/// | I/O error while writing the armored output                | [`EncryptError::Io`]              |
/// | Armor output is not valid UTF‑8 (should never occur)      | [`EncryptError::Failed`]          |
///
/// # Security Considerations
///
/// * **Non‑deterministic** – Every encryption of the same plaintext with
///   the same passphrase yields a distinct ciphertext, thanks to random
///   nonces.
/// * **Confidentiality only** – Passphrase‑based encryption does not
///   authenticate the sender. If sender authenticity is required, use
///   key‑based encryption with X25519 identities.
/// * **Tamper‑proof** – The underlying AEAD construction detects any
///   modification of the ciphertext or its armor envelope.
/// * **Passphrase strength** – The passphrase is the only secret. Use a
///   long, high‑entropy passphrase (e.g., diceware) and never hard‑code
///   it in source code.
/// * **Text‑safe** – The armor format uses only printable ASCII
///   characters and fixed‑width lines, making it compatible with
///   virtually any text‑based transport.
/// * **Memory** – The passphrase is moved into a `SecretString` and
///   zeroized after the scrypt identity is created. The armored output
///   is kept in memory as a single `String`; for very large plaintexts,
///   consider streaming the encryption directly with the `age` crate.
///
/// # Example
///
/// ```rust
/// # fn main() -> age_crypto::errors::Result<()> {
/// let plaintext = b"Unlock code: 4821";
/// let pass = "correct horse battery staple";
///
/// // Encrypt with armor
/// let armored = age_crypto::encrypt_with_passphrase_armor(plaintext, pass)?;
///
/// // Verify the armor envelope
/// assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
/// assert!(armored.len() > 50); // armor is never empty
///
/// // Decrypt to get back the original message
/// let decrypted = age_crypto::decrypt_with_passphrase_armor(&armored, pass)?;
/// assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// * [`encrypt_with_passphrase`] – binary (non‑armored) variant.
/// * [`encrypt_armor`] – key‑based armored encryption.
/// * [`decrypt_with_passphrase_armor`] – the decryption counterpart.
pub fn encrypt_with_passphrase_armor(plaintext: &[u8], passphrase: &str) -> Result<ArmoredData> {
    let secret = SecretString::from(passphrase.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(secret);
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
