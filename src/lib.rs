//! An implementation of the Third-Party Auditor role for the 
//! [Signal Key Transparency Log.](https://github.com/signalapp/key-transparency-server)

use sha2::Sha256;

use crypto_common::OutputSizeUser;
use generic_array::GenericArray;

pub mod auditor;
pub mod log;
pub mod prefix;
pub mod transparency;

/// Protocol buffer definitions for transparency log network messages.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/transparency.rs"));
}

type Hash = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;
/// Convert a vector of bytes into a hash.
///
/// # Errors
///
/// Returns an error if the input is not 32 bytes.
fn try_into_hash(x: Vec<u8>) -> Result<Hash, String> {
    let arr: [u8; 32] = x.try_into().map_err(|_| "Invalid hash")?;
    Ok(arr.into())
}

type Index = [u8; 32];
type Seed = [u8; 16];

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use proto::AuditorProof;
    use proto::AuditorUpdate;
    use proto::auditor_proof::{NewTree, Proof};
    use transparency::TransparencyLog;

    //real=true, index=72304a54df58d7d2673f7f99fe1689ca939eebc55741f3d1335904cb9c8564e4, seed=c3009d216ad487428a6f904ede447bc9, commitment=5f799a1d6d34dffacbec4d47c4f200a6be09de9b6d444ad27e87ba0beaad3607, proof=newTree{}
    // logRoot = 1e6fdd7508a05b5ba2661f7eec7e8df0a0ee9a277ca5b345f17fbe8e6aa8e9d1
    #[test]
    fn test_initialize() {
        let mut log = TransparencyLog::new();
        let index =
            hex!("72304a54df58d7d2673f7f99fe1689ca939eebc55741f3d1335904cb9c8564e4").to_vec();
        let seed = hex!("c3009d216ad487428a6f904ede447bc9").to_vec();
        let commitment =
            hex!("5f799a1d6d34dffacbec4d47c4f200a6be09de9b6d444ad27e87ba0beaad3607").into();
        let proof = Some(AuditorProof {
            proof: Some(Proof::NewTree(NewTree {})),
        });

        let expected_log_root =
            hex!("1e6fdd7508a05b5ba2661f7eec7e8df0a0ee9a277ca5b345f17fbe8e6aa8e9d1").into();

        let update = AuditorUpdate {
            real: true,
            index,
            seed,
            commitment,
            proof,
        };

        log.apply_update(update).unwrap();

        assert!(log.is_initialized());
        assert_eq!(log.log_root().unwrap(), expected_log_root);
    }
}
