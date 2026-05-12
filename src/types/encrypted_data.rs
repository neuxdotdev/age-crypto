use std::fmt;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData(Vec<u8>);
impl EncryptedData {
    #[must_use]
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl AsRef<[u8]> for EncryptedData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl From<Vec<u8>> for EncryptedData {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}
impl From<EncryptedData> for Vec<u8> {
    fn from(data: EncryptedData) -> Self {
        data.0
    }
}
impl fmt::Display for EncryptedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[EncryptedData: {} bytes]", self.0.len())
    }
}
