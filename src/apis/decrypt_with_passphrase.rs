use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use age::secrecy::SecretString;
use std::io::Read;
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let secret = SecretString::from(passphrase.to_string());
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))?;
    let identity = age::scrypt::Identity::new(secret);
    let mut decrypted = Vec::new();
    decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| DecryptError::Failed(e.to_string()))?
        .read_to_end(&mut decrypted)
        .map_err(|e| DecryptError::Failed(e.to_string()))?;
    Ok(decrypted)
}
