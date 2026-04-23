use std::fmt;
use std::ops::Deref;

/// A newtype over [`String`] representing an **armor-encoded** age encrypted file.
///
/// # Overview
///
/// Age supports two output formats:
/// - **Binary** (raw bytes) → [`EncryptedData`]
/// - **Armored** (PEM‑like text) → `ArmoredData`
///
/// `ArmoredData` is the armored version. It is guaranteed to be valid UTF‑8 and
/// contains the `-----BEGIN AGE ENCRYPTED FILE-----` header and corresponding
/// footer. The inner string is kept private; the only way to obtain an instance
/// is through the crate’s encryption functions (e.g., [`encrypt_armor`]).
///
/// # Why a newtype and not just `String`?
///
/// - **Type safety** – a function that expects an armored string can require
///   `ArmoredData`, preventing accidental use of arbitrary strings.
/// - **Encapsulation** – the value can only be created inside the library,
///   ensuring the contained string actually came from an age encryption.
/// - **Ergonomics** – by implementing [`Deref<Target = str>`] and
///   [`AsRef<str>`], you can use `ArmoredData` everywhere a `&str` is
///   accepted without manual conversion.
/// - **Privacy‑aware [`Display`]** – the `Display` implementation shows only
///   the number of characters, not the full armored text, avoiding accidental
///   leaks when logging or formatting errors.
///
/// # Invariants
///
/// An `ArmoredData` value always:
/// - Contains a valid UTF‑8 string.
/// - Begins with `-----BEGIN AGE ENCRYPTED FILE-----`.
/// - Contains the line `-----END AGE ENCRYPTED FILE-----`.
///
/// These invariants are guaranteed by the crate’s encryption functions (
/// they check the output of `age` and reject anything that doesn’t parse
/// as valid armor). Therefore, once an `ArmoredData` exists, you can rely
/// on it being a complete age‑armored ciphertext.
///
/// # Examples
///
/// ```ignore
/// use age_crypto::encrypt_armor;
///
/// let armored: ArmoredData = encrypt_armor(b"Hello", &["age1recipient..."])?;
/// println!("{}", armored);            // [ArmoredData: 1234 chars]
/// println!("{}", armored.as_str());   // prints the full PEM
/// assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmoredData(String);

impl ArmoredData {
    /// Creates a new `ArmoredData` from an already‑validated armored string.
    ///
    /// This constructor is **crate‑private** (`pub(crate)`) because the
    /// invariants of `ArmoredData` (valid armor markers, etc.) must be
    /// enforced. The public encryption APIs are the only place where such
    /// validation happens, so they alone can call this.
    ///
    /// The caller must ensure `data` is a well‑formed age armor string.
    #[must_use]
    pub(crate) fn new(data: String) -> Self {
        Self(data)
    }

    /// Returns the full armored text as a string slice.
    ///
    /// This gives read‑only access to the underlying PEM data. Use this when
    /// you need to write the armored file to disk, send it over the network,
    /// or pass it to another library.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let pem_string: &str = armored_data.as_str();
    /// std::fs::write("secret.age", pem_string)?;
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the length of the armored text in characters (not bytes).
    ///
    /// Since the content is ASCII‑armored, the byte length and character
    /// length are the same. This is just a convenience wrapper over
    /// [`str::len`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the armored text is empty.
    ///
    /// In practice, a valid age armor is never empty, but this method is
    /// provided for API completeness.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Checks whether a given string `s` looks like a valid age‑armored file.
    ///
    /// This is a convenience utility that does **not** parse the full age
    /// header or verify the cryptographic content. It only checks that the
    /// string starts with the standard `BEGIN` marker and contains the
    /// `END` marker somewhere after it.
    ///
    /// Use this for lightweight preliminary validation before attempting
    /// a full decryption with [`decrypt_armor`].
    ///
    /// # Returns
    ///
    /// `true` if `s` begins with `-----BEGIN AGE ENCRYPTED FILE-----`
    ///
    /// **and** contains `-----END AGE ENCRYPTED FILE-----`.
    #[must_use]
    pub fn is_valid_armored(s: &str) -> bool {
        s.starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
            && s.contains("-----END AGE ENCRYPTED FILE-----")
    }
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

/// Allows `&ArmoredData` to be used as a `&str`.
///
/// This makes it possible to pass an `ArmoredData` directly to functions
/// that accept `&str`, such as writing to a file or sending over a socket,
/// without calling `.as_str()` manually.
impl AsRef<str> for ArmoredData {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Enables transparent dereferencing to [`str`].
///
/// Because `ArmoredData` derefs to `str`, you can call **any** `str` method
/// directly on an `ArmoredData` value. For example:
///
/// ```ignore
/// let armored: ArmoredData = ...;
/// if armored.contains("AGE ENCRYPTED FILE") { ... }
/// let lines = armored.lines();
/// ```
///
/// This is the primary ergonomic feature of the newtype. Combined with
/// `AsRef<str>`, it integrates `ArmoredData` seamlessly into the standard
/// string ecosystem.
impl Deref for ArmoredData {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Converts an owned [`String`] into an `ArmoredData`.
///
/// **Important:** This conversion is provided for convenience but **does not**
/// validate that the string is actually a valid age armor. It is the caller’s
/// responsibility to ensure the string satisfies the invariants of
/// `ArmoredData`. In practice, only the crate’s own encryption functions
/// should use it.
impl From<String> for ArmoredData {
    fn from(data: String) -> Self {
        Self(data)
    }
}

/// Moves the armored string out of the wrapper.
///
/// This consumes the `ArmoredData` and returns the internal [`String`],
/// which can then be further manipulated or stored.
impl From<ArmoredData> for String {
    fn from(data: ArmoredData) -> Self {
        data.0
    }
}

/// Displays a concise, privacy‑preserving representation.
///
/// Instead of printing the entire armor (which could be thousands of
/// characters), the `Display` implementation shows only the character
/// count. This prevents accidental leaking of ciphertext into logs,
/// terminal output, or error messages.
///
/// If you need the full text, use [`as_str()`](ArmoredData::as_str) or
/// dereference the value.
impl fmt::Display for ArmoredData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ArmoredData: {} chars]", self.0.len())
    }
}
