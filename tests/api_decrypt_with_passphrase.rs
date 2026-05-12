use age_crypto::{DecryptError, Error, decrypt_with_passphrase, encrypt_with_passphrase};
const TEST_PASSPHRASE: &str = "correct-horse-battery-staple-🔐";
const WRONG_PASSPHRASE: &str = "wrong-passphrase-❌";
fn valid_ciphertext(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
    encrypt_with_passphrase(plaintext, passphrase)
        .expect("Test setup: encryption should succeed")
        .to_vec()
}
#[test]
fn test_decrypt_with_passphrase_basic_success() {
    let test_cases = [
        (b"" as &[u8], "empty"),
        (b"x", "single byte"),
        (b"Hello, World!", "ascii text"),
        ("🔐 Unicode 中文 🗝️".as_bytes(), "unicode"),
        (&[0u8; 1000], "1KB zeros"),
        (&[255u8; 5000], "5KB 0xFF"),
    ];
    for (plaintext, label) in test_cases {
        let ciphertext = valid_ciphertext(plaintext, TEST_PASSPHRASE);
        let decrypted = decrypt_with_passphrase(&ciphertext, TEST_PASSPHRASE)
            .unwrap_or_else(|_| panic!("Decryption should succeed for: {}", label));
        assert_eq!(decrypted, plaintext, "Mismatch for test case: {}", label);
    }
}
#[test]
fn test_decrypt_roundtrip_consistency() {
    let plaintext = b"Consistency test data \xF0\x9F\x94\x84";
    for _ in 0..5 {
        let ciphertext = encrypt_with_passphrase(plaintext, TEST_PASSPHRASE).unwrap();
        let decrypted = decrypt_with_passphrase(ciphertext.as_bytes(), TEST_PASSPHRASE).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
#[test]
fn test_decrypt_wrong_passphrase_returns_error() {
    let ciphertext = valid_ciphertext(b"secret", TEST_PASSPHRASE);
    let result = decrypt_with_passphrase(&ciphertext, WRONG_PASSPHRASE);
    assert!(
        result.is_err(),
        "Decryption with wrong passphrase should fail"
    );
    match result.unwrap_err() {
        Error::Decrypt(DecryptError::Failed(_)) => {}
        other => panic!("Expected DecryptError::Failed, got: {:?}", other),
    }
}
#[test]
fn test_decrypt_empty_ciphertext() {
    let result = decrypt_with_passphrase(&[], TEST_PASSPHRASE);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Decrypt(DecryptError::InvalidCiphertext(_))
    ));
}
#[test]
fn test_decrypt_garbage_input() {
    let garbage_inputs: Vec<&[u8]> = vec![
        b"not age ciphertext",
        b"-----BEGIN WRONG-----",
        &[0u8; 100],
        &[255u8; 50],
        b"AGE-ENC\x00\x01\x02",
    ];
    for input in garbage_inputs {
        let result = decrypt_with_passphrase(input, TEST_PASSPHRASE);
        assert!(
            result.is_err(),
            "Garbage input should fail: {:?}",
            std::str::from_utf8(input).unwrap_or("<binary>")
        );
    }
}
#[test]
fn test_decrypt_truncated_ciphertext() {
    let full_ct = valid_ciphertext(b"important data", TEST_PASSPHRASE);
    for truncate_at in [0, 10, full_ct.len() / 2, full_ct.len() - 1] {
        if truncate_at < full_ct.len() {
            let truncated = &full_ct[..truncate_at];
            let result = decrypt_with_passphrase(truncated, TEST_PASSPHRASE);
            assert!(
                result.is_err(),
                "Truncated ciphertext at {} should fail",
                truncate_at
            );
        }
    }
}
#[test]
fn test_decrypt_corrupted_ciphertext_bit_flip() {
    let mut ciphertext = valid_ciphertext(b"Sensitive info", TEST_PASSPHRASE);
    for pos in [0, 10, ciphertext.len() / 2, ciphertext.len() - 1] {
        if pos < ciphertext.len() {
            let original = ciphertext[pos];
            ciphertext[pos] ^= 0xFF;
            let result = decrypt_with_passphrase(&ciphertext, TEST_PASSPHRASE);
            assert!(
                result.is_err(),
                "Corrupted ciphertext (pos {}) should fail",
                pos
            );
            ciphertext[pos] = original;
        }
    }
}
#[test]
fn test_decrypt_appended_data_fails() {
    let mut ciphertext = valid_ciphertext(b"original", TEST_PASSPHRASE);
    ciphertext.extend_from_slice(b"extra garbage appended");
    let result = decrypt_with_passphrase(&ciphertext, TEST_PASSPHRASE);
    assert!(
        result.is_err(),
        "Ciphertext with appended data should fail authentication"
    );
}
#[test]
fn test_decrypt_prepend_data_fails() {
    let ciphertext = valid_ciphertext(b"original", TEST_PASSPHRASE);
    let mut with_prefix = b"garbage prefix ".to_vec();
    with_prefix.extend(ciphertext);
    let result = decrypt_with_passphrase(&with_prefix, TEST_PASSPHRASE);
    assert!(result.is_err(), "Prefixed ciphertext should fail");
}
#[test]
fn test_decrypt_does_not_leak_info_on_wrong_pass() {
    let ciphertext = valid_ciphertext(b"secret", TEST_PASSPHRASE);
    let long_pass = "x".repeat(100);
    let wrong_passes: Vec<&str> = vec!["", "a", "wrong", &long_pass];
    for wrong_pass in wrong_passes {
        let result = decrypt_with_passphrase(&ciphertext, wrong_pass);
        assert!(result.is_err(), "Wrong pass '{}' should fail", wrong_pass);
        match result.unwrap_err() {
            Error::Decrypt(DecryptError::Failed(_)) => {}
            Error::Decrypt(DecryptError::InvalidCiphertext(_)) => {}
            other => panic!("Unexpected error for wrong pass: {:?}", other),
        }
    }
}
#[test]
fn test_decrypt_passphrase_case_sensitive() {
    let plaintext = b"Case sensitive test";
    let ct = valid_ciphertext(plaintext, "MyPass");
    for wrong in ["mypass", "MYPASS", "MyPass ", " MyPass"] {
        let result = decrypt_with_passphrase(&ct, wrong);
        assert!(result.is_err(), "Passphrase '{}' should not work", wrong);
    }
    let decrypted = decrypt_with_passphrase(&ct, "MyPass").unwrap();
    assert_eq!(decrypted, plaintext);
}
#[test]
fn test_decrypt_utf8_passphrase_handling() {
    let long_unicode = "🎉🎊🎁".repeat(10);
    let unicode_passes: Vec<&str> = vec!["🔐emoji", "пароль", "密码", &long_unicode];
    for pass in unicode_passes {
        let plaintext = b"Unicode passphrase test";
        let ct = valid_ciphertext(plaintext, pass);
        let decrypted = decrypt_with_passphrase(&ct, pass).unwrap();
        assert_eq!(decrypted, plaintext);
        let mut wrong = pass.to_string();
        wrong.push('x');
        assert!(decrypt_with_passphrase(&ct, &wrong).is_err());
    }
}
#[test]
fn test_decrypt_large_ciphertext_10mb() {
    let plaintext = vec![0x7B; 10 * 1024 * 1024];
    let ciphertext = valid_ciphertext(&plaintext, TEST_PASSPHRASE);
    let decrypted = decrypt_with_passphrase(&ciphertext, TEST_PASSPHRASE)
        .expect("Large data decryption should succeed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(decrypted.len(), plaintext.len());
}
#[test]
fn test_decrypt_many_small_ciphertexts() {
    for i in 0..10 {
        let plaintext = format!("msg-{}", i).into_bytes();
        let ct = valid_ciphertext(&plaintext, TEST_PASSPHRASE);
        let decrypted = decrypt_with_passphrase(&ct, TEST_PASSPHRASE).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
#[test]
fn test_decrypt_concurrent_decryptions() {
    use std::thread;
    let ciphertexts: Vec<_> = (0..6)
        .map(|i| {
            let pt = vec![i as u8; 5000];
            let pass = format!("pass-{}", i);
            let ct = valid_ciphertext(&pt, &pass);
            (ct, pass, pt)
        })
        .collect();
    let handles: Vec<_> = ciphertexts
        .into_iter()
        .map(|(ct, pass, expected)| {
            thread::spawn(move || {
                let decrypted = decrypt_with_passphrase(&ct, &pass).unwrap();
                assert_eq!(decrypted, expected);
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("Decryption thread should not panic");
    }
}
#[test]
fn test_decrypt_reuse_ciphertext_multiple_times() {
    let plaintext = b"Reusable ciphertext";
    let ciphertext = valid_ciphertext(plaintext, TEST_PASSPHRASE);
    for _ in 0..5 {
        let decrypted = decrypt_with_passphrase(&ciphertext, TEST_PASSPHRASE).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
#[test]
fn test_decrypt_output_is_fresh_allocation() {
    let plaintext = b"Fresh alloc test";
    let ciphertext = valid_ciphertext(plaintext, TEST_PASSPHRASE);
    let decrypted1 = decrypt_with_passphrase(&ciphertext, TEST_PASSPHRASE).unwrap();
    let decrypted2 = decrypt_with_passphrase(&ciphertext, TEST_PASSPHRASE).unwrap();
    assert_ne!(
        decrypted1.as_ptr(),
        decrypted2.as_ptr(),
        "Decrypted outputs should be separate allocations"
    );
    assert_eq!(decrypted1, decrypted2);
}
#[test]
fn test_decrypt_does_not_mutate_input_ciphertext() {
    let plaintext = b"Immutable input";
    let ciphertext = valid_ciphertext(plaintext, TEST_PASSPHRASE);
    let original = ciphertext.clone();
    let _decrypted = decrypt_with_passphrase(&ciphertext, TEST_PASSPHRASE).unwrap();
    assert_eq!(ciphertext, original, "Ciphertext should not be mutated");
}
