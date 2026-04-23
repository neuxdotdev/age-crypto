use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::ArmoredData;
use age::armor::{ArmoredWriter, Format};
use age::secrecy::SecretString;
use std::io::Write;
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
