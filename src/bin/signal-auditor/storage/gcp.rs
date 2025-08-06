//! A storage backend using a GCP bucket
//! The intended usage is to enforce a retention lock on the bucket
//! Because the client always uses the lexicographically latest file in
//! the bucket, it will not be tricked into starting from an old head and
//! potentially equivocating on the log root.
//!
//! In order for this technique to be effective, the bucket name must be included in
//! the image measurement used to gate the auditor signing key

use crate::client::ClientConfig;
use crate::storage::{MacKey, Storage, deserialize_head, serialize_head};
use google_cloud_storage::client::{Client, ClientConfig as GcpClientConfig};
use google_cloud_storage::http::objects::download::Range;
use google_cloud_storage::http::objects::get::GetObjectRequest;
use google_cloud_storage::http::objects::list::ListObjectsRequest;
use google_cloud_storage::http::objects::upload::{Media, UploadObjectRequest, UploadType};
use hex::ToHex;
use signal_auditor::transparency::TransparencyLog;

/// A storage backend using a GCP bucket
pub struct GcpBackend {
    bucket: String,
    client: Client,
    mac_key: MacKey,
}

/// Format head path as `head_{size}_{log_root_hash}`
/// where `size` is a 16-character hex string and `log_root_hash` is a 64-character hex string
fn get_head_path(head: &TransparencyLog) -> Result<String, anyhow::Error> {
    Ok(format!(
        "head_{:016x}_{}",
        head.size(),
        head.log_root()?.encode_hex::<String>()
    ))
}

impl GcpBackend {
    pub async fn new(bucket: &str, mac_key: MacKey) -> Result<Self, anyhow::Error> {
        let config = GcpClientConfig::default().with_auth().await?;
        let client = Client::new(config);

        Ok(Self {
            bucket: bucket.to_string(),
            client,
            mac_key,
        })
    }
}

impl Storage for GcpBackend {
    async fn init_from_config(
        config: &ClientConfig,
        mac_key: MacKey,
    ) -> Result<Self, anyhow::Error> {
        let bucket = config
            .gcp_bucket
            .as_ref()
            .ok_or(anyhow::anyhow!("GCP bucket not set"))?;
        tracing::info!("Using GCP storage bucket {bucket}");
        Self::new(bucket, mac_key)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to initialize GCP storage: {}", e))
    }

    // Commits head to a file `head_{size}_{log_root_hash}`
    // then updates `head` to point to the new file
    async fn commit_head(&self, head: &TransparencyLog) -> Result<(), anyhow::Error> {
        let serialized = serialize_head(&self.mac_key, head)?;

        let path = get_head_path(head)?;
        let upload_type = UploadType::Simple(Media::new(path.clone()));
        self.client
            .upload_object(
                &UploadObjectRequest {
                    bucket: self.bucket.clone(),
                    if_generation_match: Some(0), // never overwrite
                    ..Default::default()
                },
                serialized,
                &upload_type,
            )
            .await?;
        Ok(())
    }

    // Gets head from most recent object by lexicographic order
    async fn get_head(&self) -> Result<Option<TransparencyLog>, anyhow::Error> {
        let mut objects = self
            .client
            .list_objects(&ListObjectsRequest {
                bucket: self.bucket.clone(),
                ..Default::default()
            })
            .await?;

        while objects.next_page_token.is_some() {
            objects = self
                .client
                .list_objects(&ListObjectsRequest {
                    bucket: self.bucket.clone(),
                    page_token: objects.next_page_token,
                    ..Default::default()
                })
                .await?;
        }

        let objects = objects
            .items
            .ok_or(anyhow::anyhow!("Head listing returned none"))?;
        let head_object = objects
            .last()
            .ok_or(anyhow::anyhow!("Head listing empty"))?;
        let head_file_path = head_object.name.clone();

        let head_file_data = self
            .client
            .download_object(
                &GetObjectRequest {
                    bucket: self.bucket.clone(),
                    object: head_file_path.clone(),
                    ..Default::default()
                },
                &Range::default(),
            )
            .await?;
        let head = deserialize_head(&self.mac_key, &head_file_data)?;

        // For now, verify consistency with the object name
        // TODO - verify a signature over the data
        if get_head_path(&head)? != head_object.name {
            return Err(anyhow::anyhow!(
                "Head file path mismatch: wanted {:?}, got {:?}",
                head_file_path,
                get_head_path(&head)?
            ));
        }

        Ok(Some(head))
    }
}
