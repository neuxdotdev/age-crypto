
use age_crypto::{decrypt, Error};
use age_crypto::errors::DecryptError;
fn main() {
    match decrypt(b"not-a-valid-age-file", "invalid-key") {
        Ok(_) => unreachable!(),
        Err(Error::Decrypt(DecryptError::InvalidIdentity(msg))) =>
            println!("Identity is malformed: {}", msg),
        Err(Error::Decrypt(DecryptError::InvalidCiphertext(msg))) =>
            println!("Ciphertext is malformed: {}", msg),
        Err(other) =>
            println!("Other error: {}", other),
    }
}