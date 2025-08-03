//! A trait for storage backends.
//! 
//! Currently we do not actually use generic storage impls
//! but instead use feature flags to select a single storage backend
//! 
//! TODO - sign stored data to ensure integrity

use crate::client::ClientConfig;
use signal_auditor::transparency::TransparencyLog;

// Currently we do not actually use generic storage impls
// but instead use feature flags to select the storage backend

#[cfg(feature = "storage-gcp")]
mod gcp;
#[cfg(feature = "storage-gcp")]
pub use gcp::GcpBackend as Backend;

#[cfg(not(feature = "storage-gcp"))]
mod filestore;
#[cfg(not(feature = "storage-gcp"))]
pub use filestore::FileBackend as Backend;

#[allow(async_fn_in_trait)]
pub trait Storage: Sized {
    /// Initialize the storage from a config
    async fn init_from_config(config: &ClientConfig) -> Result<Self, anyhow::Error>;

    /// Commit a log head to storage
    async fn commit_head(&self, head: &TransparencyLog) -> Result<(), anyhow::Error>;

    /// Get the log head from storage, if it exists
    /// Returns None if the storage is not initialized
    async fn get_head(&self) -> Result<Option<TransparencyLog>, anyhow::Error>;
}

// TODO - sign stored data to ensure integrity
