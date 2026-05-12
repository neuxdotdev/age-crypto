use std::fmt;
use zeroize::Zeroize;
pub struct Passphrase {
    inner: Vec<u8>,
}
impl Passphrase {
    pub fn new(passphrase: &str) -> Self {
        Self {
            inner: passphrase.as_bytes().to_vec(),
        }
    }
    #[must_use]
    pub fn expose(&self) -> &str {
        std::str::from_utf8(&self.inner).expect("Passphrase must be valid UTF-8")
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
impl Drop for Passphrase {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}
impl Clone for Passphrase {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passphrase")
            .field("len", &self.inner.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}
impl fmt::Display for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}
