//! Passphrase‑based decryption of armored age ciphertexts.

use crate::apis::decrypt_with_passphrase;
use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use age::armor::ArmoredReader;
use std::io::Read;

/// Decrypts an armor‑encoded age ciphertext that was encrypted with a passphrase.
///
/// This function removes the armor using [`ArmoredReader`] and then decrypts
/// the resulting binary ciphertext with [`decrypt_with_passphrase`].
pub fn decrypt_with_passphrase_armor(armored: &str, passphrase: &str) -> Result<Vec<u8>> {
    // Step 1: remove armor to get binary ciphertext
    let mut reader = ArmoredReader::new(armored.as_bytes());
    let mut ciphertext = Vec::new();
    reader
        .read_to_end(&mut ciphertext)
        .map_err(|e| DecryptError::InvalidCiphertext(e.to_string()))?;

    // Step 2: binary decryption
    decrypt_with_passphrase(&ciphertext, passphrase)
}