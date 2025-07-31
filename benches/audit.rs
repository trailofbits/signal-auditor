use criterion::{Criterion, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use rand::{TryRngCore, rngs::OsRng};
use signal_auditor::{
    auditor::{Auditor, DeploymentMode, PublicConfig},
    transparency::TransparencyLog,
};
use std::hint::black_box;
use std::fs;
use signal_auditor::proto::transparency;

mod test_vectors {
    include!(concat!(env!("OUT_DIR"), "/test_vectors.rs"));
}

fn load_test_vectors() -> test_vectors::TestVectors {
    let data = fs::read("tests/kt_test_vectors.pb").expect("Failed to read test vectors");
    prost::Message::decode(data.as_slice()).expect("Failed to decode test vectors")
}

fn benchmark_sequential_log_updates(c: &mut Criterion) {
    let test_vectors = load_test_vectors();
    let should_succeed = test_vectors
        .should_succeed
        .expect("No should_succeed test vectors found");

    let mut group = c.benchmark_group("sequential_log_updates");
    group.sample_size(800);
    group.measurement_time(std::time::Duration::from_secs(10));

    // Benchmark individual updates
    group.bench_function("sequential_updates", |b| {
        let mut log = TransparencyLog::new();
        let updates = should_succeed.updates.clone();
        let n = updates.len();
        let mut queue = updates.iter().cycle();
        let mut i = 0;
        b.iter(|| {
            if i % n == 0 {
                log = TransparencyLog::new();
            }
            let update = queue.next().unwrap();
            log.apply_update(update.update.as_ref().unwrap().clone())
                .unwrap();
            black_box(log.log_root().unwrap());
            i += 1;
        });
    });

    group.finish();
}

fn benchmark_head_signing(c: &mut Criterion) {
    let test_vectors = load_test_vectors();
    let should_succeed = test_vectors
        .should_succeed
        .expect("No should_succeed test vectors found");

    // Create an auditor with random keys for signing
    let mut key_bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut key_bytes).unwrap();
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let config = PublicConfig {
        mode: DeploymentMode::ThirdPartyAuditing,
        sig_key: verifying_key,
        vrf_key: verifying_key, // Using same key for simplicity in benchmark
    };

    let auditor = Auditor::new(config, signing_key);

    // Apply all updates to get a final log state
    let mut log = TransparencyLog::new();
    for update_and_hash in &should_succeed.updates {
        let update = update_and_hash.update.as_ref().unwrap();
        log.apply_update(update.clone()).unwrap();
    }

    let final_root = log.log_root().unwrap();
    let final_size = log.size();

    let mut group = c.benchmark_group("head_signing");
    group.sample_size(100);
    group.measurement_time(std::time::Duration::from_secs(10));

    group.bench_function("sign_head", |b| {
        b.iter(|| {
            let signature = auditor.sign_head(black_box(final_root), black_box(final_size));
            black_box(signature);
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .measurement_time(std::time::Duration::from_secs(10))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = benchmark_sequential_log_updates, benchmark_head_signing
);
criterion_main!(benches);
