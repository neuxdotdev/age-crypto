use crate::apis::encrypt_with_passphrase;
use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::ArmoredData;
use age::armor::{ArmoredWriter, Format};
use std::io::Write;
pub fn encrypt_with_passphrase_armor(plaintext: &[u8], passphrase: &str) -> Result<ArmoredData> {
    let encrypted = encrypt_with_passphrase(plaintext, passphrase)?;
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
