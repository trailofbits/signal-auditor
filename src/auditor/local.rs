//! The Auditor module implements the signing functionality
//! for a third party auditor.
//!
//! Log tracking is not included in this module

use crate::proto::transparency::AuditorTreeHead;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;

use crate::Hash;
use crate::auditor::PublicConfig;
use std::time::{SystemTime, UNIX_EPOCH};

/// `Auditor` holds a signing key and a public configuration.
pub struct Auditor {
    pub config: PublicConfig,
    pub key: SigningKey,
}

impl Auditor {
    /// Sign a log head at the current time.
    pub async fn sign_head(&self, head: Hash, size: u64) -> Result<AuditorTreeHead, anyhow::Error> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let msg = self.config.encode_at_time(head, size, ts as i64);
        let sig = self.key.sign(&msg);
        Ok(AuditorTreeHead {
            tree_size: size,
            signature: sig.to_vec(),
            timestamp: ts as i64,
        })
    }

    // Used for testing
    pub fn sign_at_time(&self, head: Hash, size: u64, timestamp: i64) -> AuditorTreeHead {
        let msg = self.config.encode_at_time(head, size, timestamp);
        let sig = self.key.sign(&msg);
        AuditorTreeHead {
            tree_size: size,
            signature: sig.to_vec(),
            timestamp,
        }
    }
}
