use age_crypto::{decrypt_with_passphrase, encrypt_with_passphrase};
use std::collections::HashSet;
fn test_passphrases() -> Vec<String> {
    vec![
        "simple".into(),
        "MyP@ssw0rd!2024".into(),
        "🔐emoji-passphrase🗝️".into(),
        "中文密码测试".into(),
        "a".repeat(100),
        "pass with spaces and symbols !@#$%^&*()".into(),
    ]
}
fn assert_roundtrip(plaintext: &[u8], passphrase: &str) {
    let encrypted = encrypt_with_passphrase(plaintext, passphrase).expect("Encryption failed");
    let decrypted =
        decrypt_with_passphrase(encrypted.as_bytes(), passphrase).expect("Decryption failed");
    assert_eq!(
        decrypted,
        plaintext,
        "Roundtrip mismatch for pass: {}",
        &passphrase[..passphrase.len().min(10)]
    );
}
#[test]
fn test_basic_encrypt_success() {
    let plaintext = b"Hello, secure world!";
    for passphrase in test_passphrases() {
        let encrypted = encrypt_with_passphrase(plaintext, &passphrase).unwrap();
        assert!(
            !encrypted.as_bytes().is_empty(),
            "Ciphertext must not be empty"
        );
        assert!(
            encrypted.len() > plaintext.len(),
            "Ciphertext must include headers/overhead"
        );
    }
}
#[test]
#[ignore]
fn test_roundtrip_all_passphrases() {
    let test_cases: Vec<&[u8]> = vec![
        b"",
        b"x",
        b"Hello World",
        "🎉 Unicode: 日本語, العربية, 🚀".as_bytes(),
        &[0u8; 100],
        &[255u8; 1000],
    ];
    for pt in test_cases {
        for pass in test_passphrases() {
            assert_roundtrip(pt, &pass);
        }
    }
}
#[test]
fn test_empty_plaintext() {
    assert_roundtrip(b"", "any-pass");
}
#[test]
fn test_different_passphrases_differ() {
    let pt = b"Same plaintext";
    let enc1 = encrypt_with_passphrase(pt, "pass-one").unwrap();
    let enc2 = encrypt_with_passphrase(pt, "pass-two").unwrap();
    assert_ne!(
        enc1.as_bytes(),
        enc2.as_bytes(),
        "Different keys must yield different ciphertexts"
    );
    assert!(decrypt_with_passphrase(enc1.as_bytes(), "pass-two").is_err());
    assert!(decrypt_with_passphrase(enc2.as_bytes(), "pass-one").is_err());
}
#[test]
fn test_randomized_output() {
    let pt = b"Test randomized output";
    let pass = "test-pass";
    let mut cts = HashSet::new();
    for _ in 0..5 {
        cts.insert(
            encrypt_with_passphrase(pt, pass)
                .unwrap()
                .as_bytes()
                .to_vec(),
        );
    }
    assert_eq!(
        cts.len(),
        5,
        "Encryption must produce unique ciphertexts per call"
    );
}
#[test]
fn test_wrong_passphrase_fails() {
    let encrypted = encrypt_with_passphrase(b"Secret", "correct").unwrap();
    let res = decrypt_with_passphrase(encrypted.as_bytes(), "wrong");
    assert!(res.is_err(), "Wrong passphrase must fail");
    assert!(
        matches!(
            res.unwrap_err(),
            age_crypto::Error::Decrypt(age_crypto::DecryptError::Failed(_))
        ),
        "Expected DecryptError::Failed"
    );
}
#[test]
fn test_passphrase_length_boundary() {
    assert_roundtrip(b"Boundary", "x");
    let long_pass = "a".repeat(1000);
    assert_roundtrip(b"Boundary", &long_pass);
}
#[test]
fn test_unicode_extreme() {
    let long_emoji = "🎉🎊🎈🎁🎀".repeat(100);
    let long_crab = "🦀".repeat(10000);
    let test_strings = [
        "🔐🗝️🔑🗝🔓",
        "Здравствуй мир",
        "مرحبا بالعالم",
        "こんにちは世界",
        &long_emoji,
        &long_crab,
    ];
    for s in test_strings {
        assert_roundtrip(s.as_bytes(), "unicode-pass");
    }
}
#[test]
fn test_binary_patterns() {
    let patterns: Vec<Vec<u8>> = vec![
        vec![0x00; 1000],
        vec![0xFF; 1000],
        (0..255).cycle().take(1000).collect(),
        (0..1000).map(|i| (i % 256) as u8).collect(),
    ];
    for pt in patterns {
        assert_roundtrip(&pt, "binary-test");
    }
}
#[test]
fn test_single_byte_representative() {
    let samples = [0, 1, 127, 128, 255, 42, 200, 254];
    for &byte in &samples {
        assert_roundtrip(&[byte], "test-pass");
    }
}
#[test]
#[ignore]
fn test_single_byte_exhaustive() {
    for byte in 0u8..=255 {
        assert_roundtrip(&[byte], "test-pass");
    }
}
#[test]
#[ignore]
fn test_large_data_10mb() {
    let plaintext = vec![0x5A; 10 * 1024 * 1024];
    assert_roundtrip(&plaintext, "large-test-10mb");
}
#[test]
fn test_large_data_1mb() {
    let plaintext = vec![0x5A; 1024 * 1024];
    assert_roundtrip(&plaintext, "large-test-1mb");
}
#[test]
fn test_concurrent_encryptions() {
    use std::thread;
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let pt = vec![i as u8; 10_000];
            let pass = format!("thread-{}", i);
            thread::spawn(move || {
                let enc = encrypt_with_passphrase(&pt, &pass).unwrap();
                let dec = decrypt_with_passphrase(enc.as_bytes(), &pass).unwrap();
                assert_eq!(dec, pt);
            })
        })
        .collect();
    for h in handles {
        h.join().expect("Thread should not panic");
    }
}
#[test]
#[ignore]
fn test_performance_iterations() {
    let pt = vec![0x42; 100_000];
    let pass = "perf-test";
    let start = std::time::Instant::now();
    let rounds = 50;
    for _ in 0..rounds {
        let enc = encrypt_with_passphrase(&pt, pass).unwrap();
        let _dec = decrypt_with_passphrase(enc.as_bytes(), pass).unwrap();
    }
    let elapsed = start.elapsed();
    println!("✅ {} roundtrips took {:?}", rounds, elapsed);
    assert!(elapsed.as_secs() < 60, "Performance regression detected");
}
#[test]
fn test_output_no_aliasing() {
    let pt = b"Aliasing test";
    let enc1 = encrypt_with_passphrase(pt, "pass").unwrap();
    let enc2 = encrypt_with_passphrase(pt, "pass").unwrap();
    assert_ne!(
        enc1.as_bytes().as_ptr(),
        enc2.as_bytes().as_ptr(),
        "Encrypted outputs must be independent heap allocations"
    );
}
#[test]
fn test_no_input_mutation() {
    let pt = vec![0xAB; 1000];
    let original = pt.clone();
    let _ = encrypt_with_passphrase(&pt, "test").unwrap();
    assert_eq!(pt, original, "Input buffer must remain immutable");
}
