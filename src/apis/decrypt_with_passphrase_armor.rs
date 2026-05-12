use crate::apis::decrypt_with_passphrase;
use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use age::armor::ArmoredReader;
use std::io::Read;
pub fn decrypt_with_passphrase_armor(armored: &str, passphrase: &str) -> Result<Vec<u8>> {
    let mut reader = ArmoredReader::new(armored.as_bytes());
    let mut ciphertext = Vec::new();
    reader
        .read_to_end(&mut ciphertext)
        .map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))?;
    decrypt_with_passphrase(&ciphertext, passphrase)
}
