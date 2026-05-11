//! Passphrase‑based encryption to armored age ciphertexts.

use crate::apis::encrypt_with_passphrase;
use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::ArmoredData;
use age::armor::{ArmoredWriter, Format};
use std::io::Write;

/// Encrypts plaintext with a passphrase and returns the result in **armor‑encoded** format.
///
/// This function first encrypts using [`encrypt_with_passphrase`], then wraps the binary
/// ciphertext in an armor envelope.
pub fn encrypt_with_passphrase_armor(plaintext: &[u8], passphrase: &str) -> Result<ArmoredData> {
    // Step 1: binary encryption (already well-tested)
    let encrypted = encrypt_with_passphrase(plaintext, passphrase)?;

    // Step 2: wrap binary ciphertext in ASCII armor
    let mut armored = Vec::new();
    let mut writer = ArmoredWriter::wrap_output(&mut armored, Format::AsciiArmor)
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    writer
        .write_all(encrypted.as_bytes())
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| EncryptError::Failed(e.to_string()))?;

    let armored_str = String::from_utf8(armored)
        .map_err(|e| EncryptError::Failed(format!("Armor output not UTF-8: {}", e)))?;
    Ok(ArmoredData::new(armored_str))
}