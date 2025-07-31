// TODO - consider generic S3 backend + custom auth
// TODO - sign the stored data

use crate::storage::Storage;
use crate::transparency::TransparencyLog;
use google_cloud_storage::client::{Client, ClientConfig as GcpClientConfig};
use google_cloud_storage::http::objects::get::GetObjectRequest;
use google_cloud_storage::http::objects::upload::{UploadType, Media, UploadObjectRequest};
use google_cloud_storage::http::objects::list::ListObjectsRequest;
use google_cloud_storage::http::objects::download::Range;
use crate::client::ClientConfig;

use hex::ToHex;

pub struct GcpBackend {
    bucket: String,
    client: Client,
}

impl GcpBackend {
    pub async fn new(bucket: &str) -> Result<Self, anyhow::Error> {
        let config = GcpClientConfig::default().with_auth().await?;
        let client = Client::new(config);

        Ok(Self { bucket: bucket.to_string(), client })
    }
}

fn get_head_path(head: &TransparencyLog) -> Result<String, anyhow::Error> {
    Ok(format!("head_{}_{}", head.size(), head.log_root()?.encode_hex::<String>()))
}

impl Storage for GcpBackend {
    async fn init_from_config(config: &ClientConfig) -> Result<Self, anyhow::Error> {
        let bucket = config.gcp_bucket.as_ref().ok_or(anyhow::anyhow!("GCP bucket not set"))?;
        println!("Using GCP storage bucket {}", bucket);
        Self::new(bucket).await.map_err(|e| anyhow::anyhow!("Failed to initialize GCP storage: {}", e))
    }

    // Commits head to a file `head_{size}_{log_root_hash}`
    // then updates `head` to point to the new file
    async fn commit_head(&self, head: &TransparencyLog) -> Result<(), anyhow::Error> {
        let serialized = serde_cbor::to_vec(head)?;
        
        let path = get_head_path(head)?;
        let upload_type = UploadType::Simple(Media::new(path.clone()));
        self.client.upload_object(&UploadObjectRequest {
            bucket: self.bucket.clone(),
            if_generation_match: Some(0), // never overwrite
            ..Default::default()
        }, serialized, &upload_type)
        .await?;


        // Write current head path to a file `head`
        let upload_type = UploadType::Simple(Media::new("head"));
        self.client.upload_object(&UploadObjectRequest {
            bucket: self.bucket.clone(),
            ..Default::default()
        }, path, &upload_type)
        .await?;

        Ok(())
    }

    // Gets head from most recent file by lexicographic order
    async fn get_head(&self) -> Result<Option<TransparencyLog>, anyhow::Error> {
        // Fetch the head file
        let head_path = self.client.download_object(&GetObjectRequest{
            bucket: self.bucket.clone(),
            object: "head".to_string(),
            ..Default::default()
        }, &Range::default()).await?;
        let head_path = String::from_utf8(head_path)?;


        // Fetch all objects lexicographically greater than the claimed head
        let objects = self.client.list_objects(&ListObjectsRequest {
            bucket: self.bucket.clone(),
            start_offset: Some(head_path),
            ..Default::default()
        }).await?;
        if let Some(mut objects) = objects.items {
            if let Some(head_object) = objects.pop() {
                if let Some(alternate_head_object) = objects.pop() {
                    return Err(anyhow::anyhow!("Found head file more recent than indexed value: {:?} vs {:?}", &head_object, &alternate_head_object));
                }
                let head_file_path = head_object.name;
                let head_file_data = self.client.download_object(&GetObjectRequest{
                    bucket: self.bucket.clone(),
                    object: head_file_path.clone(),
                    ..Default::default()
                }, &Range::default()).await?;
                let head: TransparencyLog = serde_cbor::from_slice(&head_file_data)?;

                // For now, verify consistency with the object name
                // TODO - verify a signature over the data
                if get_head_path(&head)? != head_file_path {
                    return Err(anyhow::anyhow!("Head file path mismatch: {:?} vs {:?}", get_head_path(&head)?, head_file_path));
                }

                return Ok(Some(head));
            }
        }
        Err(anyhow::anyhow!("Head listing returned none"))
    }
}
