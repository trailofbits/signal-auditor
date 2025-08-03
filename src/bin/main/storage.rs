//! A trait for storage backends.
//! 
//! Currently we do not actually use generic storage impls
//! but instead use feature flags to select a single storage backend
//! 
//! TODO - sign stored data to ensure integrity

use crate::client::ClientConfig;
use signal_auditor::transparency::TransparencyLog;
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;


type MacKey = [u8; 32];

#[cfg(feature = "storage-gcp")]
mod gcp;
#[cfg(feature = "storage-gcp")]
pub use gcp::GcpBackend as Backend;

#[cfg(not(feature = "storage-gcp"))]
mod filestore;
#[cfg(not(feature = "storage-gcp"))]
pub use filestore::FileBackend as Backend;

#[derive(Debug, Serialize, Deserialize)]
struct StoredHead {
    #[serde(with = "serde_bytes")]
    log_cache: Vec<u8>,
    #[serde(with = "serde_bytes")]
    mac: Vec<u8>,
}


#[allow(async_fn_in_trait)]
pub trait Storage: Sized {
    /// Initialize the storage from a config
    async fn init_from_config(config: &ClientConfig, mac_key: MacKey) -> Result<Self, anyhow::Error>;

    /// Commit a log head to storage
    async fn commit_head(&self, head: &TransparencyLog) -> Result<(), anyhow::Error>;

    /// Get the log head from storage, if it exists
    /// Returns None if the storage is not initialized
    async fn get_head(&self) -> Result<Option<TransparencyLog>, anyhow::Error>;
}


/// Serialize a log head to a byte vector, and include a MAC
fn serialize_head(mac_key: &MacKey, head: &TransparencyLog) -> Result<Vec<u8>, anyhow::Error> {
    let serialized = serde_cbor::ser::to_vec_packed(head)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).unwrap();
    mac.update(&serialized);
    let stored_head = StoredHead {
        log_cache: serialized,
        mac: mac.finalize().into_bytes().to_vec(),
    };
    Ok(serde_cbor::ser::to_vec_packed(&stored_head)?)
}

/// Deserialize a log head from a byte vector, and verify the MAC
fn deserialize_head(mac_key: &MacKey, head: &[u8]) -> Result<TransparencyLog, anyhow::Error> {
    let stored_head: StoredHead = serde_cbor::from_slice(&head)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).unwrap();
    mac.update(&stored_head.log_cache);
    #[cfg(not(feature = "dummy-mac"))]
    mac.verify_slice(&stored_head.mac)?;
    let log: TransparencyLog = serde_cbor::from_slice(&stored_head.log_cache)?;
    Ok(log)
}