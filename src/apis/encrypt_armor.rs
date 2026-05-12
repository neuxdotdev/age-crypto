use crate::apis::parse_recipients::parse_recipients;
use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::ArmoredData;
use age::armor::{ArmoredWriter, Format};
use std::io::Write;
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
