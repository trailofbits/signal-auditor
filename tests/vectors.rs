use ed25519_dalek::pkcs8::DecodePrivateKey;
use lazy_static::lazy_static;

use signal_kt_auditor::transparency;

use signal_kt_auditor::auditor::{Auditor, PublicConfig};

use ed25519_dalek::{VerifyingKey, SigningKey, pkcs8::DecodePublicKey};

mod test_vectors {
    include!(concat!(env!("OUT_DIR"), "/test_vectors.rs")); 
}

use test_vectors::TestVectors;
use prost::Message;
use signal_kt_auditor::TransparencyLog;
use generic_array::GenericArray;

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
        let expected_root = GenericArray::clone_from_slice(&vector.log_root);

        println!("Applying update: {:x?}", update);

        log.apply_update(update).unwrap();
        assert_eq!(log.log_root().unwrap(), expected_root);
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
        
        println!("Applying update: {:x?}", update);

        result = log.apply_update(update);
       }

       // TODO - assert particular errors
        assert!(result.is_err(), "Expected error {}", description);
    }
}

#[test]
fn test_signatures() {
    let vector = VECTORS.signature.clone().unwrap();
    let config = PublicConfig {
        mode: (vector.deployment_mode as u8).try_into().unwrap(),
        sig_key: VerifyingKey::from_public_key_der(vector.sig_pub_key.as_slice()).unwrap(),
        vrf_key: VerifyingKey::from_public_key_der(vector.vrf_pub_key.as_slice()).unwrap(),        
    };

    let key = SigningKey::from_pkcs8_der(vector.auditor_priv_key.as_slice()).unwrap();

    let auditor = Auditor::new(config, key);

    let head = GenericArray::clone_from_slice(&vector.root);
    let sig = auditor.sign_at_time(head, vector.tree_size,vector.timestamp as u64).unwrap();
    assert_eq!(sig, vector.signature);
}
