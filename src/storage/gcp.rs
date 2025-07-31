// TODO - consider generic S3 backend + custom auth
// TODO - sign the stored data

use crate::client::ClientConfig;
use crate::storage::Storage;
use crate::transparency::TransparencyLog;
use google_cloud_storage::client::{Client, ClientConfig as GcpClientConfig};
use google_cloud_storage::http::objects::download::Range;
use google_cloud_storage::http::objects::get::GetObjectRequest;
use google_cloud_storage::http::objects::list::ListObjectsRequest;
use google_cloud_storage::http::objects::upload::{Media, UploadObjectRequest, UploadType};

use hex::ToHex;

pub struct GcpBackend {
    bucket: String,
    client: Client,
}

fn get_head_path(head: &TransparencyLog) -> Result<String, anyhow::Error> {
    Ok(format!(
        "head_{:016x}_{}",
        head.size(),
        head.log_root()?.encode_hex::<String>()
    ))
}

impl GcpBackend {
    pub async fn new(bucket: &str) -> Result<Self, anyhow::Error> {
        let config = GcpClientConfig::default().with_auth().await?;
        let client = Client::new(config);

        Ok(Self {
            bucket: bucket.to_string(),
            client,
        })
    }
}

impl Storage for GcpBackend {
    async fn init_from_config(config: &ClientConfig) -> Result<Self, anyhow::Error> {
        let bucket = config
            .gcp_bucket
            .as_ref()
            .ok_or(anyhow::anyhow!("GCP bucket not set"))?;
        println!("Using GCP storage bucket {bucket}");
        Self::new(bucket)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to initialize GCP storage: {}", e))
    }

    // Commits head to a file `head_{size}_{log_root_hash}`
    // then updates `head` to point to the new file
    async fn commit_head(&self, head: &TransparencyLog) -> Result<(), anyhow::Error> {
        let serialized = serde_cbor::ser::to_vec_packed(head)?;

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

        // Write current head path to a file `head`
        let upload_type = UploadType::Simple(Media::new("head"));
        self.client
            .upload_object(
                &UploadObjectRequest {
                    bucket: self.bucket.clone(),
                    ..Default::default()
                },
                path,
                &upload_type,
            )
            .await?;

        Ok(())
    }

    // Gets head from most recent file by lexicographic order
    async fn get_head(&self) -> Result<Option<TransparencyLog>, anyhow::Error> {
        // Fetch the head file
        let head_path = self
            .client
            .download_object(
                &GetObjectRequest {
                    bucket: self.bucket.clone(),
                    object: "head".to_string(),
                    ..Default::default()
                },
                &Range::default(),
            )
            .await?;
        let head_path = String::from_utf8(head_path)?;
        println!("Head path: {head_path}");

        let mut objects = self
            .client
            .list_objects(&ListObjectsRequest {
                bucket: self.bucket.clone(),
                start_offset: Some(head_path),
                ..Default::default()
            })
            .await?;

        while objects.next_page_token.is_some() {
            // Fetch all objects lexicographically greater than the claimed head
            // Head index is just informative - we don't trust it to point to
            // the most recent object.
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
        let head: TransparencyLog = serde_cbor::from_slice(&head_file_data)?;

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
