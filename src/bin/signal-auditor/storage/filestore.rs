//! A storage backend using a single local file
//! This is the default storage backend and is used when no other
//! storage backend feature is enabled.
//! This backend is primarily used for testing and development.
//! No special care is taken to ensure that the file is not corrupted

use crate::client::ClientConfig;
use crate::storage::{Storage, deserialize_head, serialize_head};
use signal_auditor::transparency::TransparencyLog;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub struct FileBackend {
    path: PathBuf,
}

impl FileBackend {
    pub fn new(path: &Path) -> Result<Self, anyhow::Error> {
        // Create the directory if it doesn't exist
        std::fs::create_dir_all(path.parent().unwrap())?;
        tracing::info!("Using file storage: {}", path.display());
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

impl Storage for FileBackend {
    async fn init_from_config(config: &ClientConfig) -> Result<Self, anyhow::Error> {
        Self::new(
            config
                .storage_path
                .as_ref()
                .ok_or(anyhow::anyhow!("Storage path not set"))?,
        )
    }

    async fn commit_head(&mut self, head: &TransparencyLog) -> Result<(), anyhow::Error> {
        let serialized = serialize_head(head)?;

        let mut file = File::create(&self.path)?;
        file.write_all(&serialized)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    }

    async fn get_head(&mut self) -> Result<Option<TransparencyLog>, anyhow::Error> {
        if !self.path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&self.path)?;
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)?;
        let log_head = deserialize_head(&file_data)?;
        Ok(Some(log_head)) // TODO - return error if the log is invalid
    }
}
