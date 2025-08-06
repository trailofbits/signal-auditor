//! The Auditor module implements the signing functionality
//! for a third party auditor.

use crate::Hash;
use crate::auditor::PublicConfig;
use crate::proto::transparency::AuditorTreeHead;
use std::time::{SystemTime, UNIX_EPOCH};

use gcloud_kms::{
    client::{Client, ClientConfig},
    grpc::kms::v1::{
        AsymmetricSignRequest, GetPublicKeyRequest, crypto_key_version::CryptoKeyVersionAlgorithm,
        public_key::PublicKeyFormat,
    },
};

/// `Auditor` holds a public configuration and a reference to a KMS key version.
pub struct Auditor {
    pub config: PublicConfig,
    pub key_name: String,
}

// Gets the auditor public key as PEM from a KMS key version.
impl Auditor {
    pub async fn get_public_key(kms_name: &str) -> Result<String, anyhow::Error> {
        let client_config = ClientConfig::default().with_auth().await?;
        let client = Client::new(client_config).await?;

        let key_version = client
            .get_public_key(
                GetPublicKeyRequest {
                    name: kms_name.to_string(),
                    public_key_format: PublicKeyFormat::Pem.into(),
                },
                None,
            )
            .await?;

        if key_version.algorithm() != CryptoKeyVersionAlgorithm::EcSignEd25519 {
            return Err(anyhow::anyhow!("Key version algorithm is not Ed25519"));
        }

        Ok(key_version.pem)
    }

    /// Sign a log head at the current time.
    pub async fn sign_head(&self, head: Hash, size: u64) -> Result<AuditorTreeHead, anyhow::Error> {
        // TODO: consider keeping a client alive
        let client_config = ClientConfig::default().with_auth().await?;
        let client = Client::new(client_config).await?;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let msg = self.config.encode_at_time(head, size, ts as i64);
        let sig = client
            .asymmetric_sign(
                AsymmetricSignRequest {
                    name: self.key_name.clone(),
                    data: msg.to_vec(),
                    ..Default::default()
                },
                None,
            )
            .await?;

        Ok(AuditorTreeHead {
            tree_size: size,
            signature: sig.signature,
            timestamp: ts as i64,
        })
    }
}
