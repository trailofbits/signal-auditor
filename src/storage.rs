use crate::transparency::TransparencyLog;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Write;




pub trait Storage {
    // Commit a log head to storage
    fn commit_head(&self, head: &TransparencyLog) -> Result<(), anyhow::Error>;

    /// Get the log head from storage, if it exists
    /// Returns None if the storage is not initialized
    ///
    /// # Errors
    ///
    /// Returns an error if an OS error occurs or the log data is invalid
    fn get_head(&self) -> Result<Option<TransparencyLog>, anyhow::Error>;
}

pub struct FileStorage {
    path: PathBuf,
}

impl FileStorage {
    pub fn new(path: &Path) -> Result<Self, anyhow::Error> {
        // Create the directory if it doesn't exist
        std::fs::create_dir_all(path.parent().unwrap())?;

        Ok(Self { path: path.to_path_buf() })
    }
}

impl Storage for FileStorage {
    fn commit_head(&self, head: &TransparencyLog) -> Result<(), anyhow::Error> {
        let serialized = serde_cbor::to_vec(head)?;

        let mut file = File::create(&self.path)?;
        file.write_all(&serialized)?;
        Ok(())
    }

    fn get_head(&self) -> Result<Option<TransparencyLog>, anyhow::Error> {
        if !self.path.exists() {
            return Ok(None);
        }

        let file = File::open(&self.path)?;
        let log_head: TransparencyLog = serde_cbor::from_reader(file)?;
        Ok(Some(log_head)) // TODO - return error if the log is invalid
    }
}



// TODO - sign stored data to ensure integrity