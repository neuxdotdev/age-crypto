use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use age_setup::build_keypair;
use age_crypto::{
    encrypt_armor, decrypt_armor,
    encrypt_with_passphrase_armor, decrypt_with_passphrase_armor,
};

fn bench_armor_encrypt_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("armor_encrypt_key");
    let sizes = [16, 1024, 1024 * 1024];
    let keypair = build_keypair().expect("keygen");
    let recipient = keypair.public.expose();

    for &size in &sizes {
        let plaintext = vec![0xEE; size];
        group.bench_with_input(
            BenchmarkId::new("size", format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    encrypt_armor(black_box(&plaintext), black_box(&[recipient]))
                        .expect("armor encrypt failed");
                });
            },
        );
    }
    group.finish();
}

fn bench_armor_decrypt_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("armor_decrypt_key");
    let sizes = [16, 1024, 1024 * 1024];
    let keypair = build_keypair().expect("keygen");
    let recipient = keypair.public.expose();
    let secret = keypair.secret.expose();

    for &size in &sizes {
        let plaintext = vec![0xDD; size];
        let armored = encrypt_armor(&plaintext, &[recipient]).expect("encrypt");
        group.bench_with_input(
            BenchmarkId::new("size", format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    decrypt_armor(black_box(armored.as_str()), black_box(secret))
                        .expect("armor decrypt failed");
                });
            },
        );
    }
    group.finish();
}

fn bench_armor_passphrase(c: &mut Criterion) {
    let mut group = c.benchmark_group("armor_passphrase");
    let sizes = [16, 1024, 1024 * 1024];
    let pass = "armor-passphrase-bench";

    for &size in &sizes {
        let plaintext = vec![0xFF; size];
        let armored = encrypt_with_passphrase_armor(&plaintext, pass).expect("encrypt");
        group.bench_with_input(
            BenchmarkId::new("size", format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    decrypt_with_passphrase_armor(black_box(armored.as_str()), black_box(pass))
                        .expect("passphrase armor decrypt failed");
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_armor_encrypt_key,
    bench_armor_decrypt_key,
    bench_armor_passphrase,
);
criterion_main!(benches);