//! The Transparency Log is a Log Tree that tracks public key registrations.
//! 
//! 
//! Each leaf is a pair (`prefix_root`, `commitment`)
//! where `prefix_root` is the root of the prefix tree
//! that tracks key versions, and `commitment` is the
//! commitment to the public key.

use sha2::{Digest, Sha256};
use std::mem;
use serde::{Serialize, Deserialize};

use crate::log::LogTreeCache;
use crate::prefix::PrefixTreeCache;

use crate::{Hash, try_into_hash};

// TODO - this is serializing byte vecs as arrays of ints, which is not optimal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyLog {
    log_cache: LogTreeCache,
    prefix_cache: PrefixTreeCache,
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self {
            log_cache: LogTreeCache::new(),
            prefix_cache: PrefixTreeCache::new(),
        }
    }

    pub fn size(&self) -> u64 {
        self.prefix_cache.size
    }

    pub fn is_initialized(&self) -> bool {
        self.size() > 0
    }

    pub fn apply_update(&mut self, mut update: crate::proto::transparency::AuditorUpdate) -> Result<(), anyhow::Error> {
        // Take the commitment out of the update, this is not used by the prefix tree.
        let commitment = try_into_hash(mem::take(&mut update.commitment))?;

        // Consumes the update to avoid copying copaths
        self.prefix_cache.apply_update(update.try_into()?)?;
        let prefix_root = self
            .prefix_cache
            .root()
            .ok_or(anyhow::anyhow!("Prefix tree not initialized"))?;
        let leaf = log_leaf(prefix_root, commitment);
        self.log_cache.insert(&leaf);
        Ok(())
    }

    pub fn log_root(&self) -> Result<Hash, anyhow::Error> {
        if !self.is_initialized() {
            return Err(anyhow::anyhow!("Log is not initialized"));
        }
        Ok(self.log_cache.root().ok_or(anyhow::anyhow!("Log tree is empty"))?)
    }
}

fn log_leaf(prefix_root: Hash, commitment: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(prefix_root);
    hasher.update(commitment);
    hasher.finalize().into()
}
