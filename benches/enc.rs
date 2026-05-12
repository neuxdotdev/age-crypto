use age_crypto::encrypt;
use age_setup::build_keypair;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");
    let sizes = [16, 1024, 1024 * 1024, 10 * 1024 * 1024];
    let recipient_counts = [1, 3, 10];
    for &size in &sizes {
        let plaintext = vec![0xAA; size];
        for &n_recips in &recipient_counts {
            let keypairs: Vec<_> = (0..n_recips)
                .map(|_| build_keypair().expect("keygen"))
                .collect();
            let recipients: Vec<&str> = keypairs.iter().map(|k| k.public.expose()).collect();
            group.bench_with_input(
                BenchmarkId::new("size", format!("{}B_{}recips", size, n_recips)),
                &size,
                |b, _| {
                    b.iter(|| {
                        encrypt(black_box(&plaintext), black_box(&recipients))
                            .expect("encrypt failed");
                    });
                },
            );
        }
    }
    group.finish();
}
criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
