use lazy_static::lazy_static;

use signal_auditor::proto::transparency;

mod test_vectors {
    include!(concat!(env!("OUT_DIR"), "/test_vectors.rs"));
}

use prost::Message;
use signal_auditor::transparency::TransparencyLog;
use test_vectors::TestVectors;

lazy_static! {
    static ref VECTORS: TestVectors = {
        let pb = std::fs::read("tests/kt_test_vectors.pb").unwrap();
        TestVectors::decode(pb.as_slice()).unwrap()
    };
}

#[test]
fn test_should_succeed() {
    let mut log = TransparencyLog::new();
    let should_succeed = VECTORS.should_succeed.clone().unwrap();
    for vector in should_succeed.updates.into_iter() {
        let update = vector.update.unwrap();
        let expected_root = vector.log_root;

        println!("Applying update: {update:x?}");

        log.apply_update(update).unwrap();
        assert_eq!(log.log_root().unwrap().to_vec(), expected_root);
    }
}

#[test]
fn test_should_fail() {
    let mut log = TransparencyLog::new();
    let should_fail = VECTORS.should_fail.clone();
    for vector in should_fail {
        let description = vector.description;
        let mut result = Ok(());
        for update in vector.updates.into_iter() {
            println!("Applying update: {update:x?}");

            result = log.apply_update(update);
        }

        // TODO - assert particular errors
        assert!(result.is_err(), "Expected error {description}");
    }
}

#[cfg(not(feature = "gcloud-kms"))]
#[test]
fn test_signatures() {
    let vector = VECTORS.signature.clone().unwrap();
    let key = SigningKey::from_pkcs8_der(vector.auditor_priv_key.as_slice()).unwrap();

    let config = PublicConfig {
        mode: (vector.deployment_mode as u8).try_into().unwrap(),
        sig_key: VerifyingKey::from_public_key_der(vector.sig_pub_key.as_slice()).unwrap(),
        vrf_key: VerifyingKey::from_public_key_der(vector.vrf_pub_key.as_slice()).unwrap(),
        auditor_key: key.verifying_key(),
    };

    let auditor = Auditor { config, key };

    let head = vector.root.try_into().unwrap();
    let sig = auditor.sign_at_time(head, vector.tree_size, vector.timestamp);
    assert_eq!(sig.signature, vector.signature);
}
