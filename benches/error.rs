use age_crypto::errors::{DecryptError, EncryptError, Error};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_error_creation(c: &mut Criterion) {
    c.bench_function("error_encrypt_failed", |b| {
        b.iter(|| EncryptError::Failed(black_box("test error".into())))
    });
    c.bench_function("error_decrypt_invalid_ciphertext", |b| {
        b.iter(|| DecryptError::InvalidCiphertext(black_box("bad header".into())))
    });
    c.bench_function("error_wrap_into_top_level", |b| {
        let e = DecryptError::Io(std::io::Error::new(std::io::ErrorKind::Other, "oops"));
        b.iter(|| {
            let _: Error = black_box(e.clone()).into();
        })
    });
}

fn bench_error_matching(c: &mut Criterion) {
    let err_decrypt = Error::Decrypt(DecryptError::Failed("wrong key".into()));
    let err_encrypt = Error::Encrypt(EncryptError::NoRecipients);
    c.bench_function("match_decrypt_failed", |b| {
        b.iter(|| {
            if let Error::Decrypt(DecryptError::Failed(msg)) = &err_decrypt {
                black_box(msg);
            }
        })
    });
    c.bench_function("match_encrypt_no_recipients", |b| {
        b.iter(|| {
            if let Error::Encrypt(EncryptError::NoRecipients) = &err_encrypt {
                black_box(());
            }
        })
    });
}

criterion_group!(benches, bench_error_creation, bench_error_matching);
criterion_main!(benches);
