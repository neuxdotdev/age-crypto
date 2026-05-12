use age_crypto::{decrypt, decrypt_with_passphrase, encrypt, encrypt_with_passphrase};
use age_setup::build_keypair;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_decrypt_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_key");
    let sizes = [16, 1024, 1024 * 1024];

    for &size in &sizes {
        let plaintext = vec![0xBB; size];
        let keypair = build_keypair().expect("keygen");
        let encrypted = encrypt(&plaintext, &[keypair.public.expose()]).expect("encrypt");
        let secret = keypair.secret.expose_secret();

        group.bench_with_input(
            BenchmarkId::new("size", format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = decrypt(black_box(encrypted.as_bytes()), black_box(secret))
                        .expect("decrypt failed");
                });
            },
        );
    }
    group.finish();
}

fn bench_decrypt_passphrase(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_passphrase");
    let sizes = [16, 1024, 1024 * 1024];
    let pass = "benchmark-passphrase-42";

    for &size in &sizes {
        let plaintext = vec![0xCC; size];
        let encrypted = encrypt_with_passphrase(&plaintext, pass).expect("encrypt");

        group.bench_with_input(
            BenchmarkId::new("size", format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ =
                        decrypt_with_passphrase(black_box(encrypted.as_bytes()), black_box(pass))
                            .expect("decrypt failed");
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_decrypt_key, bench_decrypt_passphrase);
criterion_main!(benches);
