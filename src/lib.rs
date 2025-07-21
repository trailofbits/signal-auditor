pub mod prefix;
pub mod log;

use sha2::{Sha256, Digest};

use crypto_common::OutputSizeUser;
use generic_array::GenericArray;

use log::LogTreeCache;
use prefix::PrefixTreeCache;

type Hash = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;

type Index = [u8; 32];
type Seed = [u8; 16];

enum TransparencyLog {
    Initialized {
        log_cache: LogTreeCache,
        prefix_cache: PrefixTreeCache,
        size: u64,
    },
    Uninitialized,
}

impl TransparencyLog {
    fn new() -> Self {
        Self::Uninitialized
    }

    fn is_initialized(&self) -> bool {
        matches!(self, Self::Initialized { .. })
    }

    fn apply_update(&mut self, update: &AuditorUpdate) -> Result<(), String> {
        if let Self::Initialized { log_cache, prefix_cache, size } = self {
            if let AuditorProof::NewTree = &update.proof {
                return Err("Already initialized".to_string());
            }

            *prefix_cache = prefix_cache.apply_update(update)?;
            let leaf = log_leaf(prefix_cache.root(), update.commitment);
            log_cache.insert(&leaf);
            *size += 1;
            Ok(())
        } else if let AuditorProof::NewTree = &update.proof {
                let prefix_cache = PrefixTreeCache::new(update.index, update.seed);
                let mut log_cache = LogTreeCache::new();
                let leaf = log_leaf(prefix_cache.root(), update.commitment);
                log_cache.insert(&leaf);
                *self = Self::Initialized {
                    log_cache,
                    prefix_cache,
                    size: 1,
                };
                return Ok(());
            } else  {
                return Err("Log is not initialized".to_string());
            }
    }

    fn log_root(&self) -> Result<Hash, String> {
        if let Self::Initialized { log_cache, .. } = self {
            Ok(log_cache.root())
        } else {
            Err("Log is not initialized".to_string())
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::Initialized { size, .. } => *size,
            Self::Uninitialized => 0,
        }
    }
}


fn log_leaf(prefix_root: Hash, commitment: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(prefix_root);
    hasher.update(commitment);
    hasher.finalize()
}

enum AuditorProof {
    NewTree,
    DifferentKey {
        copath: Vec<Hash>,
        old_seed: Seed,
    },
    SameKey {
        copath: Vec<Hash>,
        counter: u32,
        position: u64,
    },
}

struct AuditorUpdate {
    real: bool,
    index: Index,
    seed: Seed,
    commitment: Hash,
    proof: AuditorProof,
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    //real=true, index=72304a54df58d7d2673f7f99fe1689ca939eebc55741f3d1335904cb9c8564e4, seed=c3009d216ad487428a6f904ede447bc9, commitment=5f799a1d6d34dffacbec4d47c4f200a6be09de9b6d444ad27e87ba0beaad3607, proof=newTree{}
    // logRoot = 1e6fdd7508a05b5ba2661f7eec7e8df0a0ee9a277ca5b345f17fbe8e6aa8e9d1
    #[test]
    fn test_initialize() {
        let mut log = TransparencyLog::new();
        let index = hex!("72304a54df58d7d2673f7f99fe1689ca939eebc55741f3d1335904cb9c8564e4");
        let seed = hex!("c3009d216ad487428a6f904ede447bc9");
        let commitment = hex!("5f799a1d6d34dffacbec4d47c4f200a6be09de9b6d444ad27e87ba0beaad3607").into();
        let proof = AuditorProof::NewTree;

        let expected_log_root = hex!("1e6fdd7508a05b5ba2661f7eec7e8df0a0ee9a277ca5b345f17fbe8e6aa8e9d1").into();

        let update = AuditorUpdate {
            real: true,
            index,
            seed,
            commitment,
            proof,
        };

        log.apply_update(&update).unwrap();

        assert!(log.is_initialized());
        assert_eq!(log.log_root().unwrap(), expected_log_root);
    }


}