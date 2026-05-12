use crate::apis::parse_recipients::parse_recipients;
use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::EncryptedData;
use std::io::Write;
pub fn encrypt(plaintext: &[u8], recipients: &[&str]) -> Result<EncryptedData> {
    let recipient_list = parse_recipients(recipients)?;
    let encryptor =
        age::Encryptor::with_recipients(recipient_list.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| EncryptError::Failed(e.to_string()))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| EncryptError::Failed(e.to_string()))?;
    Ok(EncryptedData::new(encrypted))
}
