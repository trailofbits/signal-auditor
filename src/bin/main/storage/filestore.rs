//! A storage backend using a single local file
//! This is the default storage backend and is used when no other
//! storage backend feature is enabled.
//! This backend is primarily used for testing and development.
//! No special care is taken to ensure that the file is not corrupted

use crate::client::ClientConfig;
use crate::storage::{serialize_head, deserialize_head, MacKey, Storage};
use signal_auditor::transparency::TransparencyLog;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct FileBackend {
    path: PathBuf,
    mac_key: MacKey,
}

impl FileBackend {
    pub fn new(path: &Path, mac_key: MacKey) -> Result<Self, anyhow::Error> {
        // Create the directory if it doesn't exist
        std::fs::create_dir_all(path.parent().unwrap())?;
        tracing::info!("Using file storage: {}", path.display());
        Ok(Self {
            path: path.to_path_buf(),
            mac_key,
        })
    }
}

impl Storage for FileBackend {
    async fn init_from_config(config: &ClientConfig, mac_key: MacKey) -> Result<Self, anyhow::Error> {
        Self::new(
            config
                .storage_path
                .as_ref()
                .ok_or(anyhow::anyhow!("Storage path not set"))?,
            mac_key,
        )
    }

    async fn commit_head(&self, head: &TransparencyLog) -> Result<(), anyhow::Error> {
        let serialized = serialize_head(&self.mac_key, head)?;

        let mut file = File::create(&self.path)?;
        file.write_all(&serialized)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    }

    async fn get_head(&self) -> Result<Option<TransparencyLog>, anyhow::Error> {
        if !self.path.exists() {
            return Ok(None);
        }

        let file = File::open(&self.path)?;
        let log_head = deserialize_head(&self.mac_key, &file)?;
        Ok(Some(log_head)) // TODO - return error if the log is invalid
    }
}
