# age-crypto

[![Crates.io](https://img.shields.io/crates/v/age-crypto.svg)](https://crates.io/crates/age-crypto)
[![Documentation](https://docs.rs/age-crypto/badge.svg)](https://docs.rs/age-crypto)
[![License](https://img.shields.io/crates/l/age-crypto.svg)](https://crates.io/crates/age-crypto)

A safe, ergonomic, and pure Rust wrapper around the [age](https://age-encryption.org/v1) encryption library. `age-crypto` provides a high-level, idiomatic API for encrypting and decrypting data using modern cryptographic primitives. It supports both **X25519 public-key encryption** and **passphrase-based encryption (scrypt)**, with options for both binary and PEM-armored (ASCII) output formats.

Designed for seamless integration with [`age-setup`](https://crates.io/crates/age-setup), this crate handles the heavy lifting of encryption while ensuring type safety and secure memory handling.

## Features

- **Multiple Encryption Modes**:
    - **Public Key (X25519)**: Encrypt data for specific recipients using their public keys.
    - **Passphrase (Scrypt)**: Encrypt data using a passphrase, suitable for backups and personal use.
- **Output Formats**:
    - **Binary**: Compact, efficient for storage and network transmission.
    - **Armored (PEM)**: Text-safe format (Base64) suitable for email, JSON, or copy-pasting.
- **Multiple Recipients**: Encrypt a single file for multiple recipients in one operation.
- **Type Safety**: Strong types (`EncryptedData`, `ArmoredData`) prevent misuse of ciphertext.
- **Secure Memory**: Automatic zeroization of sensitive data (passphrases) upon drop.
- **C Binding Support**: Full Foreign Function Interface (FFI) for integration with C/C++ projects.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
age-crypto = "0.2" # Check crates.io for the latest version
```

For key generation capabilities, we recommend using the companion crate:

```toml
[dependencies]
age-setup = "0.1"
```

---

## Quick Start

### 1. Passphrase-Based Encryption

The simplest way to encrypt data. No key management required.

```rust
use age_crypto::{encrypt_with_passphrase, decrypt_with_passphrase};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = b"My secret data";
    let passphrase = "strong-password-123";

    // Encrypt
    let encrypted = encrypt_with_passphrase(plaintext, passphrase)?;

    // Decrypt
    let decrypted = decrypt_with_passphrase(encrypted.as_bytes(), passphrase)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}
```

### 2. Public Key Encryption (with `age-setup`)

Ideal for secure communication between parties.

```rust
use age_crypto::{encrypt, decrypt};
use age_setup::build_keypair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate keys (usually done once per user)
    let keypair = build_keypair()?;
    let public_key = keypair.public.expose(); // "age1..."

    // 2. Encrypt for the recipient using their public key
    let plaintext = b"Confidential message";
    let encrypted = encrypt(plaintext, &[public_key])?;

    // 3. Decrypt using the secret key
    let decrypted = decrypt(encrypted.as_bytes(), keypair.secret.expose())?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}
```

---

## API Reference

The library provides 8 core functions divided by encryption mode and output format.

### Encryption Functions

| Function                          | Mode       | Output Format      | Description                                               |
| :-------------------------------- | :--------- | :----------------- | :-------------------------------------------------------- |
| [`encrypt`]                       | Public Key | Binary (`Vec<u8>`) | Encrypts for one or more recipients. Most compact format. |
| [`encrypt_armor`]                 | Public Key | Armored (`String`) | Encrypts for recipients, wrapped in PEM armor.            |
| [`encrypt_with_passphrase`]       | Passphrase | Binary (`Vec<u8>`) | Encrypts using a passphrase via scrypt.                   |
| [`encrypt_with_passphrase_armor`] | Passphrase | Armored (`String`) | Encrypts with passphrase, wrapped in PEM armor.           |

### Decryption Functions

| Function                          | Mode       | Input Format | Description                                          |
| :-------------------------------- | :--------- | :----------- | :--------------------------------------------------- |
| [`decrypt`]                       | Public Key | Binary       | Decrypts using a secret key (`AGE-SECRET-KEY-1...`). |
| [`decrypt_armor`]                 | Public Key | Armored      | Decrypts armored data using a secret key.            |
| [`decrypt_with_passphrase`]       | Passphrase | Binary       | Decrypts using the passphrase.                       |
| [`decrypt_with_passphrase_armor`] | Passphrase | Armored      | Decrypts armored data using the passphrase.          |

---

## Usage Guide

### Output Types

The library uses wrapper types to ensure data integrity and prevent accidental misuse.

#### `EncryptedData`

Represents raw binary encrypted data.

```rust
let data = encrypt(b"test", &[recipient])?;
let bytes: &[u8] = data.as_bytes();
let vec: Vec<u8> = data.to_vec();
```

#### `ArmoredData`

Represents ASCII-armored encrypted data. It implements `Display` to output the armored string.

```rust
let armored = encrypt_with_passphrase_armor(b"test", "pass")?;
println!("{}", armored); // Prints the full PEM block
assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
```

### Multiple Recipients

You can encrypt data for multiple recipients simultaneously. Any one of the corresponding secret keys can decrypt the file.

```rust
use age_setup::build_keypair;

let alice = build_keypair()?;
let bob = build_keypair()?;

let recipients = [alice.public.expose(), bob.public.expose()];
let encrypted = encrypt(b"Shared secret", &recipients)?;

// Bob can decrypt it
let dec = decrypt(encrypted.as_bytes(), bob.secret.expose())?;
assert_eq!(dec, b"Shared secret");
```

### Error Handling

Errors are categorized into `EncryptError` and `DecryptError` wrapped in a top-level `Error` enum.

```rust
use age_crypto::{decrypt, Error, errors::DecryptError};

match decrypt(bytes, "invalid-key") {
    Ok(_) => println!("Success"),
    Err(Error::Decrypt(DecryptError::InvalidIdentity(msg))) => {
        eprintln!("The secret key format was invalid: {}", msg);
    }
    Err(Error::Decrypt(DecryptError::Failed(msg))) => {
        eprintln!("Decryption failed (wrong key or tampered data): {}", msg);
    }
    Err(e) => eprintln!("Other error: {}", e),
}
```

---

## C/C++ Integration (FFI)

`age-crypto` provides a stable C API for use in other languages. The bindings are generated using `cbindgen`.

### Building the Shared Library

1. Ensure you have the `cdylib` crate type in your `Cargo.toml`.
2. Build with cargo:
    ```bash
    cargo build --release
    ```
    The output will be located at `target/release/libage_crypto.so` (Linux), `.dylib` (macOS), or `.dll` (Windows).

### Header File (`age-crypto.h`)

The header file defines the available functions. You can generate it using `cbindgen` or find it in the `clib/` directory of the repository.

### C API Reference

#### Memory Management

- **`age_free_string(char *s)`**: Frees a string returned by the library.
- **`age_free_bytes(uint8_t *data, size_t len)`**: Frees a byte array returned by the library.

#### Encryption

- **`age_encrypt(...)`**: Binary public key encryption.
- **`age_encrypt_armor(...)`**: Armored public key encryption.
- **`age_encrypt_with_passphrase(...)`**: Binary passphrase encryption.
- **`age_encrypt_with_passphrase_armor(...)`**: Armored passphrase encryption.

#### Decryption

- **`age_decrypt(...)`**: Binary public key decryption.
- **`age_decrypt_armor(...)`**: Armored public key decryption.
- **`age_decrypt_with_passphrase(...)`**: Binary passphrase decryption.
- **`age_decrypt_with_passphrase_armor(...)`**: Armored passphrase decryption.

### C Example

```c
#include <stdio.h>
#include <stdlib.h>
#include "age-crypto.h"

int main() {
    const char *passphrase = "my-secret-pass";
    const char *plaintext = "Hello from C!";
    size_t pt_len = 14;

    // --- Encrypt (Armored) ---
    char *armored_out = NULL;
    int res = age_encrypt_with_passphrase_armor(
        (uint8_t*)plaintext, pt_len, passphrase, &armored_out
    );

    if (res == 0 && armored_out) {
        printf("Encrypted Armored Data:\n%s\n", armored_out);

        // --- Decrypt (Armored) ---
        uint8_t *decrypted = NULL;
        size_t dec_len = 0;

        res = age_decrypt_with_passphrase_armor(armored_out, passphrase, &decrypted, &dec_len);

        if (res == 0 && decrypted) {
            printf("Decrypted: %.*s\n", (int)dec_len, decrypted);
            age_free_bytes(decrypted, dec_len);
        }

        age_free_string(armored_out);
    } else {
        printf("Encryption failed with code: %d\n", res);
    }

    return 0;
}
```

---

## Security Considerations

1.  **Memory Zeroization**: The `Passphrase` type and secret keys managed by `age-setup` are automatically zeroized when they go out of scope, minimizing the risk of secrets remaining in memory.
2.  **Nonce Management**: The library automatically generates unique nonces for every encryption operation. You do not need to manage them.
3.  **Passphrase Strength**: For passphrase-based encryption, the security relies entirely on the strength of the passphrase. Use long, high-entropy passphrases (e.g., Diceware).
4.  **Armored Data**: While armored data is base64 encoded, it is not "encrypted twice". It is simply a text-safe representation of the ciphertext.

## License

Licensed under either of

- MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Contribution

Contributions are welcome! Please ensure `cargo test` passes and run `cargo clippy` to check for linting issues before submitting a pull request.
