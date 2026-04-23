# age-crypto

A safe, ergonomic Rust wrapper around the [age](https://age-encryption.org) encryption
library. It provides a high‑level, idiomatic API for encrypting and decrypting data
using the modern age file encryption format. The crate supports both X25519 key‑based
and passphrase‑based encryption, and can produce either binary or PEM‑armored output.

This crate is designed to be used in conjunction with
[`age‑setup`](https://crates.io/crates/age‑setup), which handles secure key pair
generation, validation, and zeroized memory for secret keys. All examples in this
documentation use `age‑setup` for key management.

## Quick Start

### Passphrase‑based encryption (simplest)

```rs
use age_crypto::{encrypt_with_passphrase, decrypt_with_passphrase};

# fn main() -> age_crypto::errors::Result<()> {
let plaintext = b"secret message";
let passphrase = "strong‑passphrase‑here";

let encrypted = encrypt_with_passphrase(plaintext, passphrase)?;
let decrypted = decrypt_with_passphrase(encrypted.as_bytes(), passphrase)?;
assert_eq!(decrypted, plaintext);
# Ok(())
# }
```

### Key‑based encryption (using `age‑setup`)

```rs
use age_crypto::{encrypt, decrypt};
use age_setup::build_keypair;

# fn main() -> age_crypto::errors::Result<()> {
// Generate a key pair
let keypair = build_keypair().expect("key generation failed");
let public_key_str = keypair.public.expose();   // "age1..."
let secret_key_str = keypair.secret.expose();   // "AGE‑SECRET‑KEY‑1..."

// Encrypt with the public key
let plaintext = b"sensitive data";
let encrypted = encrypt(plaintext, &[public_key_str])?;

// Decrypt with the secret key
let decrypted = decrypt(encrypted.as_bytes(), secret_key_str)?;
assert_eq!(decrypted, plaintext);
# Ok(())
# }
```

## Key‑Based Encryption

Key‑based encryption uses X25519 public keys (`age1...`). It is suitable for:

- Secure communication between users.
- Encrypting files for multiple recipients.
- Systems with explicit key management.

### Single recipient example

```rs
use age_crypto::{encrypt, decrypt};
use age_setup::build_keypair;

# fn main() -> age_crypto::errors::Result<()> {
let recipient = build_keypair().expect("key generation failed");

let data = b"production server configuration";
let encrypted = encrypt(data, &[recipient.public.expose()])?;

// Only the holder of the matching secret key can decrypt
let decrypted = decrypt(encrypted.as_bytes(), recipient.secret.expose())?;
assert_eq!(decrypted, data);
# Ok(())
# }
```

### Multiple recipients example

```rs
use age_crypto::encrypt;
use age_crypto::decrypt;
use age_setup::build_keypair;

# fn main() -> age_crypto::errors::Result<()> {
let alice = build_keypair().expect("key generation failed");
let bob   = build_keypair().expect("key generation failed");
let carol = build_keypair().expect("key generation failed");

// Encrypt once; any of the three can decrypt with their own secret key
let recipients = [
    alice.public.expose(),
    bob.public.expose(),
    carol.public.expose(),
];

let secret_document = b"company secret";
let encrypted = encrypt(secret_document, &recipients)?;

// Alice decrypts
let decrypted = decrypt(encrypted.as_bytes(), alice.secret.expose())?;
assert_eq!(decrypted, secret_document);

// Bob can also decrypt
let decrypted = decrypt(encrypted.as_bytes(), bob.secret.expose())?;
assert_eq!(decrypted, secret_document);
# Ok(())
# }
```

## Passphrase‑Based Encryption

Passphrase‑based encryption relies on a user‑chosen secret string. It is useful for:

- Encrypted backups that can be remembered by a human.
- Personal files where key distribution is not practical.
- Scenarios where a full key management system is overkill.

### Basic example

```rs
use age_crypto::{encrypt_with_passphrase, decrypt_with_passphrase};

# fn main() -> age_crypto::errors::Result<()> {
let backup_data = b"database credentials: user=admin, pass=supersecret";
let passphrase = "MyStrongPassphrase2024!";

let encrypted = encrypt_with_passphrase(backup_data, passphrase)?;
// Store `encrypted` on disk / in cloud ...

// Later, decrypt with the same passphrase
let decrypted = decrypt_with_passphrase(encrypted.as_bytes(), passphrase)?;
assert_eq!(decrypted, backup_data);
# Ok(())
# }
```

### Passphrase strength warning

Weak passphrases can be brute‑forced. Use a long, high‑entropy passphrase.

```rs
use rand::{thread_rng, Rng};

# fn main() {
let words = ["correct", "horse", "battery", "staple", "mountain", "river"];
let mut rng = thread_rng();
let passphrase: String = (0..6)
    .map(|_| words[rng.gen_range(0..words.len())])
    .collect::<Vec<_>>()
    .join("-");
// Example output: "battery‑river‑correct‑horse‑staple‑mountain"
# let _ = passphrase;
# }
```

## Armored Output

Armor encoding wraps the encrypted data in a PEM‑like text envelope
(`-----BEGIN AGE ENCRYPTED FILE-----` / `-----END AGE ENCRYPTED FILE-----`).
It makes the ciphertext safe for text‑only channels such as email, JSON,
or copy‑paste operations.

### Passphrase‑based armored encryption

```rs
use age_crypto::{encrypt_with_passphrase_armor, decrypt_with_passphrase_armor};

# fn main() -> age_crypto::errors::Result<()> {
let config = b"api_key=sk_live_abc123xyz";
let passphrase = "deploy‑secret‑2024";

let armored = encrypt_with_passphrase_armor(config, passphrase)?;

// The output is a valid age armored string
assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

// It can be written to a text file
std::fs::write("config.age", armored.as_str()).expect("failed to write file");

// Decryption from the armored string
let loaded = std::fs::read_to_string("config.age").expect("failed to read file");
let decrypted = decrypt_with_passphrase_armor(&loaded, passphrase)?;
assert_eq!(decrypted, config);
# Ok(())
# }
```

### Binary vs Armored Comparison

| Aspect           | Binary (`encrypt`)            | Armored (`encrypt_armor`)                    |
| ---------------- | ----------------------------- | -------------------------------------------- |
| Size             | Smaller (~30% less)           | Slightly larger (base64 overhead)            |
| Format           | `Vec<u8>` (raw bytes)         | `String` (ASCII text)                        |
| Typical use case | Binary files, network streams | Configuration files, email, JSON, copy‑paste |
| Transport safety | Requires binary‑safe handling | Safe for all text‑based systems              |

## API Reference

### Public functions

| Function                          | Description                         | Return type             |
| --------------------------------- | ----------------------------------- | ----------------------- |
| [`encrypt`]                       | Binary key‑based encryption         | `Result<EncryptedData>` |
| [`encrypt_armor`]                 | Armored key‑based encryption        | `Result<ArmoredData>`   |
| [`encrypt_with_passphrase`]       | Binary passphrase‑based encryption  | `Result<EncryptedData>` |
| [`encrypt_with_passphrase_armor`] | Armored passphrase‑based encryption | `Result<ArmoredData>`   |
| [`decrypt`]                       | Binary key‑based decryption         | `Result<Vec<u8>>`       |
| [`decrypt_armor`]                 | Armored key‑based decryption        | `Result<Vec<u8>>`       |
| [`decrypt_with_passphrase`]       | Binary passphrase‑based decryption  | `Result<Vec<u8>>`       |
| [`decrypt_with_passphrase_armor`] | Armored passphrase‑based decryption | `Result<Vec<u8>>`       |

### Output types

#### `EncryptedData`

A newtype over `Vec<u8>` representing binary age‑encrypted data. It prevents
accidentally mixing plaintext and ciphertext.

```
use age_crypto::{encrypt, EncryptedData};
use age_setup::build_keypair;

# fn main() -> age_crypto::errors::Result<()> {
let keys = build_keypair().expect("key generation failed");
let encrypted: EncryptedData = encrypt(b"test", &[keys.public.expose()])?;

// Access as a byte slice
let bytes: &[u8] = encrypted.as_bytes();
// Convert to owned Vec<u8>
let owned: Vec<u8> = encrypted.to_vec();
# let _ = (bytes, owned);
# Ok(())
# }
```

#### `ArmoredData`

A newtype over `String` representing an armored age ciphertext. It provides
built‑in format validation.

```rs
use age_crypto::{encrypt_armor, ArmoredData};
use age_setup::build_keypair;

# fn main() -> age_crypto::errors::Result<()> {
let keys = build_keypair().expect("key generation failed");
let armored: ArmoredData = encrypt_armor(b"test", &[keys.public.expose()])?;

let text: &str = armored.as_str();
// Quick validation: is this a valid age armored string?
assert!(ArmoredData::is_valid_armored(text));
# Ok(())
# }
```

## Error Handling

Every function returns `age_crypto::errors::Result<T>`, an alias for
`std::result::Result<T, age_crypto::errors::Error>`. The top‑level `Error` enum
categorises failures into two groups:

- `Error::Encrypt(`[`EncryptError`]`)` – encryption‑related failures.
- `Error::Decrypt(`[`DecryptError`]`)` – decryption‑related failures.

```rs
use age_crypto::{decrypt, Error};
use age_crypto::errors::DecryptError;

# fn example(ciphertext: &[u8], key: &str) {
match decrypt(ciphertext, key) {
    Ok(plaintext) => println!("Decryption succeeded: {} bytes", plaintext.len()),
    Err(Error::Decrypt(DecryptError::InvalidIdentity(msg))) =>
        eprintln!("Malformed secret key: {}", msg),
    Err(Error::Decrypt(DecryptError::Failed(msg))) =>
        eprintln!("Wrong key or tampered data: {}", msg),
    Err(Error::Decrypt(DecryptError::InvalidCiphertext(msg))) =>
        eprintln!("Not a valid age file: {}", msg),
    other => eprintln!("Unexpected error: {:?}", other),
}
# }
```

### Error structure

```text
Error
+-- Encrypt(EncryptError)
|   +-- NoRecipients
|   +-- InvalidRecipient { recipient, reason }
|   +-- Failed(String)
|   +-- Io(io::Error)
+-- Decrypt(DecryptError)
    +-- InvalidIdentity(String)
    +-- InvalidCiphertext(String)
    +-- Failed(String)
    +-- Io(io::Error)
```

## Security Best Practices

- **Use `age‑setup` to generate key pairs** – it guarantees valid format and
  securely zeroes secret key memory on drop.
- **Never hard‑code or log secret keys or passphrases.** `SecretKey`'s
  `Display` implementation redacts the content, but you should still avoid
  printing it.
- **Use strong passphrases.** For password‑based encryption, prefer long,
  randomly generated passphrases (diceware style) or a password manager.
- **Leverage memory zeroing.** Both `age‑setup::SecretKey` and
  `age_crypto::Passphrase` are automatically zeroized on drop. For
  plaintext buffers, consider using the `zeroize` crate explicitly.
- **Do not reuse nonces.** The crate handles nonce generation automatically;
  do not attempt to override it.
- **For very large files**, consider using the lower‑level `age` streaming API
  directly to avoid loading the entire plaintext into memory at once.

## Integration with `age‑setup`

The companion crate [`age‑setup`](https://crates.io/crates/age‑setup) provides:

- Generation of X25519 key pairs (`build_keypair()`).
- Zeroizing memory for secret keys.
- Safe wrappers (`PublicKey`, `SecretKey`, `KeyPair`).

### Complete workflow: generate, encrypt, decrypt

```rs
use age_crypto::{encrypt, decrypt};
use age_setup::build_keypair;

# fn main() -> age_crypto::errors::Result<()> {
// 1. Setup: generate a key pair for a new user
let user_keys = build_keypair().expect("key generation failed");
println!("Public key (share freely): {}", user_keys.public);
// Store user_keys.secret securely – do not log it!

// 2. Encrypt: send sensitive data to this user
let sensitive = b"Q4 2024 financial report";
let encrypted = encrypt(sensitive, &[user_keys.public.expose()])?;

// 3. Transport: send `encrypted` over the network or save to a file

// 4. Decrypt: the user decrypts with their secret key
let decrypted = decrypt(encrypted.as_bytes(), user_keys.secret.expose())?;
assert_eq!(decrypted, sensitive);
# Ok(())
# }
```

## Real‑World Examples

### Secure config loader

Load an encrypted configuration file that only the application can read.

```rs
use age_crypto::decrypt_with_passphrase_armor;
use serde::Deserialize;
use std::env;
use std::error::Error;

# fn main() -> Result<(), Box<dyn Error>> {
#[derive(Deserialize)]
struct AppConfig {
    database_url: String,
    api_key: String,
}

fn load_config(armored_file: &str, pass_env_var: &str) -> Result<AppConfig, Box<dyn Error>> {
    let armored = std::fs::read_to_string(armored_file)?;
    let passphrase = env::var(pass_env_var)
        .map_err(|_| format!("Set {} environment variable", pass_env_var))?;

    let config_json = decrypt_with_passphrase_armor(&armored, &passphrase)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    let config: AppConfig = serde_json::from_slice(&config_json)?;
    Ok(config)
}
# Ok(())
# }
```

### Client‑server secure message exchange

A client encrypts a message with the server's public key; only the server
can decrypt it.

```rs
// --- Server setup (once) ---
use age_setup::build_keypair;
use std::fs;

fn setup_server_keys() -> Result<(), Box<dyn std::error::Error>> {
    let keys = build_keypair().map_err(|e| format!("Key gen failed: {}", e))?;
    fs::write("server.pub", keys.public.expose()).expect("failed to write public key");
    fs::write("server.sec", keys.secret.expose()).expect("failed to write secret key");
    // On Unix, restrict permissions
    #[cfg(unix)]
    std::process::Command::new("chmod").arg("600").arg("server.sec").status()?;
    Ok(())
}

// --- Client side ---
use age_crypto::encrypt_armor;

fn send_secure_message(server_pub_key: &str, msg: &str) -> Result<String, Box<dyn std::error::Error>> {
    let armored = encrypt_armor(msg.as_bytes(), &[server_pub_key])
        .map_err(|e| format!("Encryption failed: {}", e))?;
    Ok(armored.to_string())  // safe to send as text
}

// --- Server: receive and decrypt ---
use age_crypto::decrypt_armor;

fn receive_message(armored: &str, server_secret: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let plaintext = decrypt_armor(armored, server_secret)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    // Process plaintext ...
    Ok(plaintext)
}
# fn main() {}
```

### Automated encrypted backup

```rs
use age_crypto::encrypt_with_passphrase_armor;
use chrono::Local;
use std::{fs, path::Path};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
fn backup_and_encrypt(source_dir: &str, prefix: &str, passphrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut archive = Vec::new();
    for entry in fs::read_dir(source_dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) == Some("txt") {
            let content = fs::read(entry.path())?;
            archive.extend_from_slice(&content);
            archive.extend_from_slice(b"\n---\n");
        }
    }

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("{}_backup_{}.age", prefix, timestamp);

    let armored = encrypt_with_passphrase_armor(&archive, passphrase)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    fs::write(&filename, armored.as_str())?;
    println!("Encrypted backup saved to {}", filename);
    Ok(())
}
# Ok(())
# }
```

## License

Licensed under either of

- MIT license ([LICENSE‑MIT](LICENSE) or <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Contributions are welcome. Please ensure `cargo test` and `cargo clippy` pass
before submitting a pull request.
