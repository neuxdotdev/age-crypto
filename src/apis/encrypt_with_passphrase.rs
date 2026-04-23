use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use crate::types::EncryptedData;
use age::secrecy::SecretString;
use std::io::Write;
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<EncryptedData> {
    let secret = SecretString::from(passphrase.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(secret);
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
