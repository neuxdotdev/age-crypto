//! # Public API – Encryption & Decryption functions
//!
//! This module provides the **complete public interface** for the `age-crypto` library.
//! All operations for encrypting and decrypting data using the [age](https://age-encryption.org)
//! encryption format are exposed here, organised by:
//!
//! - **Key type**: X25519 key-based or passphrase-based.
//! - **Output format**: raw binary or PEM-armoured (text).
//!
//! ## Function overview
//!
//! | Operation | Binary (bytes) | Armored (text) |
//! |-----------|---------------|----------------|
//! | **Key‑based encrypt** | [`encrypt`] → [`EncryptedData`] | [`encrypt_armor`] → [`ArmoredData`] |
//! | **Key‑based decrypt** | [`decrypt`] → `Vec<u8>` | [`decrypt_armor`] → `Vec<u8>` |
//! | **Passphrase encrypt** | [`encrypt_with_passphrase`] → [`EncryptedData`] | [`encrypt_with_passphrase_armor`] → [`ArmoredData`] |
//! | **Passphrase decrypt** | [`decrypt_with_passphrase`] → `Vec<u8>` | [`decrypt_with_passphrase_armor`] → `Vec<u8>` |
//!
//! All functions return `crate::errors::Result<T>`, which is an alias for
//! `std::result::Result<T, crate::errors::Error>`. The error type unifies
//! encryption and decryption failures, making error handling straightforward.
//!
//! ## Quick start
//!
//! ### Key‑based encryption (binary) – using `age‑setup`
//!
//! ```
//! use age_crypto::{encrypt, decrypt};
//! use age_setup::build_keypair;
//!
//! # fn main() -> age_crypto::errors::Result<()> {
//! // Generate a key pair
//! let keypair = build_keypair().expect("key generation failed");
//! let public_key = keypair.public.expose();       // "age1..."
//! let secret_key = keypair.secret.expose();       // "AGE‑SECRET‑KEY‑1..."
//!
//! // Encrypt
//! let plaintext = b"Hello, age!";
//! let encrypted = encrypt(plaintext, &[public_key])?;
//!
//! // Decrypt
//! let decrypted = decrypt(encrypted.as_bytes(), secret_key)?;
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! ### Passphrase‑based encryption (armored)
//!
//! ```
//! use age_crypto::{encrypt_with_passphrase_armor, decrypt_with_passphrase_armor};
//!
//! # fn main() -> age_crypto::errors::Result<()> {
//! let pass = "correct horse battery staple";
//! let plaintext = b"Confidential document";
//!
//! // Encrypt to armored text
//! let armored = encrypt_with_passphrase_armor(plaintext, pass)?;
//! assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
//!
//! // Decrypt from the armored string
//! let decrypted = decrypt_with_passphrase_armor(&armored, pass)?;
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! ## Module organisation
//!
//! The following sub‑modules are **public** and contain the actual implementations:
//!
//! - [`decrypt`] / [`decrypt_armor`]
//! - [`decrypt_with_passphrase`] / [`decrypt_with_passphrase_armor`]
//! - [`encrypt`] / [`encrypt_armor`]
//! - [`encrypt_with_passphrase`] / [`encrypt_with_passphrase_armor`]
//!
//! Two additional modules are **crate‑private** (`pub(crate)`) and handle input
//! parsing, used internally by the public functions:
//!
//! - `parse_recipients` – validates and parses recipient public key strings.
//! - `parse_identity` – validates and parses a secret key string into an identity.
//!
//! ## Design principles
//!
//! - **Consistent return type** – every function returns `Result<T, Error>`, never panics.
//! - **Newtype outputs** – [`EncryptedData`] and [`ArmoredData`] carry semantic meaning
//!   and prevent accidental mixing of plaintext and ciphertext.
//! - **Transparent error conversion** – errors from lower‑level helpers are automatically
//!   promoted to the unified `Error` via `From` implementations.
//! - **Zero‑cost abstraction** – the functions are thin wrappers around the `age` crate;
//!   all heavy lifting is done by `age`.
//!
//! ## Security considerations
//!
//! - **Key management** – secret keys (`AGE‑SECRET‑KEY‑1...`) must be kept private. This
//!   library does not store or manage keys; it only uses them transiently.
//! - **Passphrase strength** – passphrase‑based encryption relies entirely on the
//!   passphrase. Use a strong, high‑entropy passphrase.
//! - **Armor format** – armored output is safe for text‑based transport but is **not**
//!   encryption itself; it simply encodes the ciphertext.
//! - **Memory safety** – passphrases are zeroized after use (via `SecretString` and
//!   `Passphrase`). However, plaintext and ciphertext are stored in standard `Vec<u8>`;
//!   for highest security, consider zeroizing them after use.

pub mod decrypt;
pub mod decrypt_armor;
pub mod decrypt_with_passphrase;
pub mod decrypt_with_passphrase_armor;
pub mod encrypt;
pub mod encrypt_armor;
pub mod encrypt_with_passphrase;
pub mod encrypt_with_passphrase_armor;
pub(crate) mod parse_identity;
pub(crate) mod parse_recipients;

pub use decrypt::decrypt;
pub use decrypt_armor::decrypt_armor;
pub use decrypt_with_passphrase::decrypt_with_passphrase;
pub use decrypt_with_passphrase_armor::decrypt_with_passphrase_armor;
pub use encrypt::encrypt;
pub use encrypt_armor::encrypt_armor;
pub use encrypt_with_passphrase::encrypt_with_passphrase;
pub use encrypt_with_passphrase_armor::encrypt_with_passphrase_armor;
