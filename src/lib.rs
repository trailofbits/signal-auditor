pub mod prefix;
pub mod log;
pub mod auditor;

use sha2::{Sha256, Digest};
use std::mem;

use crypto_common::OutputSizeUser;
use generic_array::GenericArray;

use log::LogTreeCache;
use prefix::PrefixTreeCache;

type Hash = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;

type Index = [u8; 32];
type Seed = [u8; 16];

pub mod transparency {
    include!(concat!(env!("OUT_DIR"), "/transparency.rs"));
}

pub mod test_vectors {
    include!(concat!(env!("OUT_DIR"), "/test_vectors.rs"));
}

use transparency::AuditorUpdate;
use transparency::auditor_proof::Proof;


use crate::prefix::PrefixTreeUpdate;

pub enum TransparencyLog {
    Initialized {
        log_cache: LogTreeCache,
        prefix_cache: PrefixTreeCache,
        size: u64,
    },
    Uninitialized,
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self::Uninitialized
    }

    pub fn is_initialized(&self) -> bool {
        matches!(self, Self::Initialized { .. })
    }

    pub fn apply_update(&mut self, mut update: AuditorUpdate) -> Result<(), String> {
        // Take the commitment out of the update, this is not used by the prefix tree.
        let commitment = try_into_hash(mem::take(&mut update.commitment))?;

        // Consumes the update to avoid copying copaths
        let update = PrefixTreeUpdate::try_from(update)?;

        if let Self::Initialized { log_cache, prefix_cache, size } = self {
            if let PrefixTreeUpdate::NewTree { .. } = update {
                return Err("Already initialized".to_string());
            }

            *prefix_cache = prefix_cache.apply_update(update)?;
            let leaf = log_leaf(prefix_cache.root(), commitment);
            log_cache.insert(&leaf);
            *size += 1;
            Ok(())
        } else if let PrefixTreeUpdate::NewTree { index, seed } = update {
                let prefix_cache = PrefixTreeCache::new(index, seed);
                let mut log_cache = LogTreeCache::new();
                let leaf = log_leaf(prefix_cache.root(), commitment);
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

    pub fn log_root(&self) -> Result<Hash, String> {
        if let Self::Initialized { log_cache, .. } = self {
            Ok(log_cache.root())
        } else {
            Err("Log is not initialized".to_string())
        }
    }

    pub fn size(&self) -> u64 {
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

fn try_into_hash(x: Vec<u8>) -> Result<Hash, String> {
    let arr: [u8; 32] = x.try_into().map_err(|_| "Invalid hash")?;
   Ok(arr.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use transparency::AuditorProof;
    use transparency::auditor_proof::NewTree;

    //real=true, index=72304a54df58d7d2673f7f99fe1689ca939eebc55741f3d1335904cb9c8564e4, seed=c3009d216ad487428a6f904ede447bc9, commitment=5f799a1d6d34dffacbec4d47c4f200a6be09de9b6d444ad27e87ba0beaad3607, proof=newTree{}
    // logRoot = 1e6fdd7508a05b5ba2661f7eec7e8df0a0ee9a277ca5b345f17fbe8e6aa8e9d1
    #[test]
    fn test_initialize() {
        let mut log = TransparencyLog::new();
        let index = hex!("72304a54df58d7d2673f7f99fe1689ca939eebc55741f3d1335904cb9c8564e4").to_vec();
        let seed = hex!("c3009d216ad487428a6f904ede447bc9").to_vec();
        let commitment = hex!("5f799a1d6d34dffacbec4d47c4f200a6be09de9b6d444ad27e87ba0beaad3607").into();
        let proof = Some(AuditorProof{proof: Some(Proof::NewTree(NewTree{}))});

        let expected_log_root = hex!("1e6fdd7508a05b5ba2661f7eec7e8df0a0ee9a277ca5b345f17fbe8e6aa8e9d1").into();

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