use crate::errors::Result;
use crate::errors::decrypt::DecryptError;
use std::str::FromStr;
pub(crate) fn parse_identity(secret_key: &str) -> Result<age::x25519::Identity> {
    age::x25519::Identity::from_str(secret_key)
        .map_err(|e| DecryptError::InvalidIdentity(format!("Parse failed: {}", e)).into())
}
