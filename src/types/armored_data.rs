use std::fmt;
use std::ops::Deref;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmoredData(String);
impl ArmoredData {
    #[must_use]
    pub(crate) fn new(data: String) -> Self {
        Self(data)
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    #[must_use]
    pub fn is_valid_armored(s: &str) -> bool {
        s.starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
            && s.contains("-----END AGE ENCRYPTED FILE-----")
    }
}
impl AsRef<str> for ArmoredData {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
impl Deref for ArmoredData {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<String> for ArmoredData {
    fn from(data: String) -> Self {
        Self(data)
    }
}
impl From<ArmoredData> for String {
    fn from(data: ArmoredData) -> Self {
        data.0
    }
}
impl fmt::Display for ArmoredData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ArmoredData: {} chars]", self.0.len())
    }
}
