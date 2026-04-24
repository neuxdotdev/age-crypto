use age_crypto::{decrypt_with_passphrase, encrypt_with_passphrase};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn bench_passphrase_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("passphrase_roundtrip");
    let sizes = [16, 1024, 1024 * 1024];
    let passphrases = ["a", "super-secret-long-passphrase-12345!"];

    for &size in &sizes {
        let plaintext = vec![0x77; size];
        for pass in &passphrases {
            let encrypted = encrypt_with_passphrase(&plaintext, pass).expect("encrypt");
            group.bench_with_input(
                BenchmarkId::new("size/pass", format!("{}B_{}chars", size, pass.len())),
                &size,
                |b, _| {
                    b.iter(|| {
                        let _ = decrypt_with_passphrase(
                            black_box(encrypted.as_bytes()),
                            black_box(pass),
                        )
                        .expect("decrypt failed");
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_passphrase_roundtrip);
criterion_main!(benches);
