use crate::errors::Result;
use crate::errors::encrypt::EncryptError;
use age::x25519;
use std::str::FromStr;
pub(crate) fn parse_recipients(recipients: &[&str]) -> Result<Vec<x25519::Recipient>> {
    if recipients.is_empty() {
        return Err(EncryptError::NoRecipients.into());
    }
    let mut list = Vec::with_capacity(recipients.len());
    for r in recipients {
        let recipient =
            x25519::Recipient::from_str(r).map_err(|e| EncryptError::InvalidRecipient {
                recipient: r.to_string(),
                reason: e.to_string(),
            })?;
        list.push(recipient);
    }
    Ok(list)
}
