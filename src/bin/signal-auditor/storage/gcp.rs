//! A storage backend using a GCP bucket
//! The intended usage is to enforce a retention lock on the bucket
//! Because the client always uses the lexicographically latest file in
//! the bucket, it will not be tricked into starting from an old head and
//! potentially equivocating on the log root.
//!
//! In order for this technique to be effective, the bucket name must be included in
//! the image measurement used to gate the auditor signing key

use crate::client::ClientConfig;
use crate::storage::{Storage, deserialize_head, serialize_head};
use google_cloud_storage::client::{Client, ClientConfig as GcpClientConfig};
use google_cloud_storage::http::Error;
use google_cloud_storage::http::error::ErrorResponse;
use google_cloud_storage::http::objects::download::Range;
use google_cloud_storage::http::objects::get::GetObjectRequest;
use google_cloud_storage::http::objects::upload::{Media, UploadObjectRequest, UploadType};
use signal_auditor::transparency::TransparencyLog;

const HEAD_OBJECT: &str = "log_head";

/// A storage backend using a GCP bucket
pub struct GcpBackend {
    bucket: String,
    client: Client,
    // Used to detect contention on the head object
    last_generation: Option<i64>,
}

impl GcpBackend {
    pub async fn new(bucket: &str) -> Result<Self, anyhow::Error> {
        let config = GcpClientConfig::default().with_auth().await?;
        let client = Client::new(config);

        Ok(Self {
            bucket: bucket.to_string(),
            client,
            last_generation: None,
        })
    }
}

impl Storage for GcpBackend {
    async fn init_from_config(config: &ClientConfig) -> Result<Self, anyhow::Error> {
        let bucket = config
            .gcp_bucket
            .as_ref()
            .ok_or(anyhow::anyhow!("GCP bucket not set"))?;
        tracing::info!("Using GCP storage bucket {bucket}");
        Self::new(bucket)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to initialize GCP storage: {}", e))
    }

    // Commits head to a file `head_{size}_{log_root_hash}`
    // then updates `head` to point to the new file
    async fn commit_head(&mut self, head: &TransparencyLog) -> Result<(), anyhow::Error> {
        let serialized = serialize_head(head)?;

        let upload_type = UploadType::Simple(Media::new(HEAD_OBJECT.to_string()));
        let response = self
            .client
            .upload_object(
                &UploadObjectRequest {
                    bucket: self.bucket.clone(),
                    if_generation_match: self.last_generation,
                    ..Default::default()
                },
                serialized,
                &upload_type,
            )
            .await?;
        self.last_generation = Some(response.generation);
        Ok(())
    }

    // Gets head from most recent object by lexicographic order
    async fn get_head(&mut self) -> Result<Option<TransparencyLog>, anyhow::Error> {
        let head_file = self
            .client
            .get_object(&GetObjectRequest {
                bucket: self.bucket.clone(),
                object: HEAD_OBJECT.to_string(),
                ..Default::default()
            })
            .await;

        if let Err(Error::Response(ErrorResponse { code: 404, .. })) = head_file {
            tracing::info!("No log head found, creating new log");
            return Ok(None);
        }

        let head_file = head_file?;
        self.last_generation = Some(head_file.generation);

        let head_file_data = self
            .client
            .download_object(
                &GetObjectRequest {
                    bucket: self.bucket.clone(),
                    object: HEAD_OBJECT.to_string(),
                    generation: self.last_generation,
                    ..Default::default()
                },
                &Range::default(),
            )
            .await?;
        let head = deserialize_head(&head_file_data)?;

        Ok(Some(head))
    }
}
