//! # Data types for encrypted and armored outputs, and passphrases
//!
//! This module contains the three core value types that the library’s
//! public API produces or consumes:
//!
//! - **[`EncryptedData`]** – binary (raw) age‑encrypted output.
//! - **[`ArmoredData`]** – PEM‑armored age‑encrypted output (text).
//! - **[`Passphrase`]** – a password/phrase that is zeroized on drop.
//!
//! # Design principles
//!
//! - **Newtype encapsulation** – both `EncryptedData` and `ArmoredData`
//!   wrap standard library types (`Vec<u8>` and `String`) to add semantic
//!   meaning and restrict construction to the crate’s encryption functions.
//! - **Ergonomic interop** – they implement commonly expected traits like
//!   `AsRef`, `Deref`, `From`, and `Display` so that they integrate
//!   smoothly with the Rust ecosystem.
//! - **Privacy by default** – `Display` output for all three types is
//!   deliberately limited (shows length or `[REDACTED]`) to avoid
//!   accidental logging of sensitive information.
//! - **Secure memory handling** – `Passphrase` actively zeroes its
//!   internal buffer on drop and redacts its content in debug/display
//!   formats.
//!
//! # Re‑exports
//!
//! The module publicly re‑exports its three types so you can import them
//! directly from the crate root:
//!
//! ```ignore
//! use age_crypto::EncryptedData;
//! use age_crypto::ArmoredData;
//! use age_crypto::Passphrase;
//! ```

pub mod armored_data;
pub mod encrypted_data;
pub mod passphrase;

pub use armored_data::ArmoredData;
pub use encrypted_data::EncryptedData;
pub use passphrase::Passphrase;
