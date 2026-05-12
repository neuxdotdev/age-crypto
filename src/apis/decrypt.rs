use crate::apis::parse_identity::parse_identity;
use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use std::io::Read;
pub fn decrypt(ciphertext: &[u8], secret_key: &str) -> Result<Vec<u8>> {
    let identity = parse_identity(secret_key)?;
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))?;
    let mut decrypted = Vec::new();
    decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| DecryptError::Failed(e.to_string()))?
        .read_to_end(&mut decrypted)
        .map_err(|e| DecryptError::Failed(e.to_string()))?;
    Ok(decrypted)
}
