use age_crypto::{decrypt, encrypt};
use age_setup::build_keypair;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn bench_multi_recipient(c: &mut Criterion) {
    let mut group = c.benchmark_group("recipients");
    let recipient_counts = [1, 5, 20, 50];
    let plaintext = vec![0x88; 100_000]; // 100 KB

    for &n in &recipient_counts {
        let keypairs: Vec<_> = (0..n).map(|_| build_keypair().expect("keygen")).collect();
        let recipients: Vec<&str> = keypairs.iter().map(|k| k.public.expose()).collect();

        // Benchmark encryption alone
        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{}_recips", n)),
            &n,
            |b, _| {
                b.iter(|| {
                    encrypt(black_box(&plaintext), black_box(&recipients)).expect("encrypt failed");
                });
            },
        );

        // Benchmark decryption with the first recipient's secret key
        let encrypted = encrypt(&plaintext, &recipients).expect("pre-encrypt");
        let first_secret = keypairs[0].secret.expose();
        group.bench_with_input(
            BenchmarkId::new("decrypt", format!("{}_recips", n)),
            &n,
            |b, _| {
                b.iter(|| {
                    decrypt(black_box(encrypted.as_bytes()), black_box(first_secret))
                        .expect("decrypt failed");
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_multi_recipient);
criterion_main!(benches);
