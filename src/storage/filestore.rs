use crate::client::ClientConfig;
use crate::storage::Storage;
use crate::transparency::TransparencyLog;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct FileBackend {
    path: PathBuf,
}

impl FileBackend {
    pub fn new(path: &Path) -> Result<Self, anyhow::Error> {
        // Create the directory if it doesn't exist
        std::fs::create_dir_all(path.parent().unwrap())?;
        println!("Using file storage: {}", path.display());
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

impl Storage for FileBackend {
    async fn init_from_config(config: &ClientConfig) -> Result<Self, anyhow::Error> {
        Self::new(
            &config
                .storage_path
                .as_ref()
                .ok_or(anyhow::anyhow!("Storage path not set"))?,
        )
    }

    async fn commit_head(&self, head: &TransparencyLog) -> Result<(), anyhow::Error> {
        let serialized = serde_cbor::ser::to_vec_packed(head)?;

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
        let log_head: TransparencyLog = serde_cbor::from_reader(file)?;
        Ok(Some(log_head)) // TODO - return error if the log is invalid
    }
}
