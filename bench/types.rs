use criterion::{black_box, criterion_group, criterion_main, Criterion};
use age_crypto::types::{EncryptedData, ArmoredData, Passphrase};

fn bench_encrypted_data(c: &mut Criterion) {
    let data = vec![0x42; 10_000];
    let enc = EncryptedData::from(data.clone());
    c.bench_function("encrypted_data_from", |b| {
        b.iter(|| EncryptedData::from(black_box(data.clone())))
    });
    c.bench_function("encrypted_data_as_bytes", |b| {
        b.iter(|| enc.as_bytes())
    });
    c.bench_function("encrypted_data_to_vec", |b| {
        b.iter(|| enc.to_vec())
    });
    c.bench_function("encrypted_data_into_vec", |b| {
        let owned = enc.clone();
        b.iter(|| {
            let v: Vec<u8> = black_box(owned.clone()).into();
            v
        })
    });
}

fn bench_armored_data(c: &mut Criterion) {
    let pem_str = "-----BEGIN AGE ENCRYPTED FILE-----\n... lots of base64 ...\n-----END AGE ENCRYPTED FILE-----".to_string();
    let armored = ArmoredData::from(pem_str.clone());
    c.bench_function("armored_data_from", |b| {
        b.iter(|| ArmoredData::from(black_box(pem_str.clone())))
    });
    c.bench_function("armored_as_str", |b| {
        b.iter(|| armored.as_str())
    });
    c.bench_function("armored_is_valid", |b| {
        b.iter(|| ArmoredData::is_valid_armored(black_box(armored.as_str())))
    });
    c.bench_function("armored_deref_len", |b| {
        b.iter(|| armored.len())
    });
}

fn bench_passphrase(c: &mut Criterion) {
    let p = Passphrase::new("bench-passphrase-long-enough-123");
    c.bench_function("passphrase_new", |b| {
        b.iter(|| Passphrase::new(black_box("bench-passphrase")))
    });
    c.bench_function("passphrase_expose", |b| {
        b.iter(|| p.expose())
    });
    c.bench_function("passphrase_clone", |b| {
        b.iter(|| p.clone())
    });
    c.bench_function("passphrase_drop", |b| {
        b.iter(|| {
            let tmp = Passphrase::new(black_box("temp"));
            std::mem::drop(tmp);
        })
    });
}

criterion_group!(benches, bench_encrypted_data, bench_armored_data, bench_passphrase);
criterion_main!(benches);