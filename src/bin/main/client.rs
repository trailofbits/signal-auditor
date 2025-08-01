use anyhow::Context;
use ed25519_dalek::{
    SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{collections::VecDeque, path::PathBuf};
use tonic::{Code, Request, Response, Status};

use signal_auditor::auditor::DeploymentMode;
use signal_auditor::auditor::{Auditor, PublicConfig};
use signal_auditor::proto::kt::{
    AuditRequest, AuditResponse, key_transparency_service_client::KeyTransparencyServiceClient,
};
use signal_auditor::transparency::TransparencyLog;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::storage::{Backend, Storage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// The server endpoint to connect to (e.g., "https://example.com:443")
    pub server_endpoint: String,
    /// Path to the client certificate file (PEM format)
    pub client_cert_path: PathBuf,
    /// Path to the client private key file (PEM format)
    pub client_key_path: PathBuf,
    /// Path to the CA certificate file (PEM format) for server verification
    pub ca_cert_path: Option<PathBuf>,
    /// Default batch size for audit requests
    pub default_batch_size: u64,
    /// Maximum number of retries for failed requests - TODO
    pub max_retries: u32,
    /// Timeout for requests in seconds
    pub request_timeout_seconds: u64,
    /// KT Log Public Key
    pub signal_public_key: PathBuf,
    /// VRF Public Key
    pub vrf_public_key: PathBuf,
    /// Auditor signing key
    pub auditor_signing_key: PathBuf,
    /// Poll interval for audit seconds
    pub poll_interval_seconds: u64,
    /// Maximum number of concurrent requests to queue
    pub max_concurrent_requests: usize,

    /// GCP bucket name
    #[cfg(feature = "storage-gcp")]
    pub gcp_bucket: Option<String>,

    /// Path to the storage file
    #[cfg(not(feature = "storage-gcp"))]
    pub storage_path: Option<PathBuf>,
}

pub struct KeyTransparencyClient {
    endpoint: Endpoint,
    config: ClientConfig,
    transparency_log: TransparencyLog,
    storage: Backend,
    auditor: Auditor, // holds the key material for the auditor
}

impl KeyTransparencyClient {
    /// Create a new client with the given configuration
    pub async fn new(config: ClientConfig) -> Result<Self, anyhow::Error> {
        let identity = Identity::from_pem(
            std::fs::read(&config.client_cert_path).context("Failed to read client cert")?,
            std::fs::read(&config.client_key_path).context("Failed to read client key")?,
        );

        let mut tls_config = ClientTlsConfig::new().identity(identity);
        if let Some(ca_cert_path) = &config.ca_cert_path {
            let ca_certificate = Certificate::from_pem(std::fs::read(ca_cert_path)?);
            tls_config = tls_config.ca_certificate(ca_certificate);
        } else {
            tls_config = tls_config.with_enabled_roots();
        }

        let storage = Backend::init_from_config(&config)
            .await
            .context("Failed to initialize storage backend")?;

        let transparency_log = storage
            .get_head()
            .await
            .context("Error trying to get log head")?
            .unwrap_or_else(|| {
                tracing::info!("No log head found, creating new log");
                TransparencyLog::new()
            });

        // Read auditor settings
        let signal_public_key = std::fs::read_to_string(&config.signal_public_key)
            .context("Failed to read signal public key")?;
        let vrf_public_key = std::fs::read_to_string(&config.vrf_public_key)
            .context("Failed to read VRF public key")?;
        let auditor_signing_key = std::fs::read_to_string(&config.auditor_signing_key)
            .context("Failed to read auditor signing key")?;

        let auditor_config = PublicConfig {
            mode: DeploymentMode::ThirdPartyAuditing, // Assume third party auditing, since we're an auditor...
            sig_key: VerifyingKey::from_public_key_pem(&signal_public_key)
                .context("Failed to parse signal public key")?,
            vrf_key: VerifyingKey::from_public_key_pem(&vrf_public_key)
                .context("Failed to parse VRF public key")?,
        };

        let auditor_key = SigningKey::from_pkcs8_pem(&auditor_signing_key)
            .context("Failed to parse auditor signing key")?;

        let auditor = Auditor::new(auditor_config, auditor_key);

        let endpoint = Endpoint::from_shared(config.server_endpoint.clone())
            .context("Failed to create endpoint")?
            .tls_config(tls_config)
            .context("Failed to create TLS config")?
            .timeout(Duration::from_secs(config.request_timeout_seconds));

        Ok(Self {
            endpoint,
            config,
            transparency_log,
            storage,
            auditor,
        })
    }

    /// Returns true if there are updates at the given index
    async fn test_at_index(
        &self,
        client: &mut KeyTransparencyServiceClient<Channel>,
        index: u64,
    ) -> Result<bool, anyhow::Error> {
        let response =
            fetch_audit_entries(&self.config, &mut client.clone(), index, Some(1), false).await;
        match response {
            Ok(response) => Ok(!response.updates.is_empty()),
            Err(status) => {
                if status.code() == Code::OutOfRange {
                    Ok(false)
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to fetch audit entries at index {index}: {:?}",
                        status
                    ))
                }
            }
        }
    }

    /// Estimate the end of the log by binary search
    pub async fn estimate_log_end(&mut self) -> Result<u64, anyhow::Error> {
        let transport = self
            .endpoint
            .connect()
            .await
            .context("Failed to connect to server")?;
        let mut client = KeyTransparencyServiceClient::new(transport);
        // Start at known base and keep doubling until we get an empty response
        let mut low = self.transparency_log.size();
        let mut high = 1;
        while self.test_at_index(&mut client, high).await? {
            high *= 2;
        }

        // Now binary search between low and high
        while high - low > 500 {
            let mid = (low + high) / 2;
            if self.test_at_index(&mut client, mid).await? {
                low = mid;
            } else {
                high = mid + 1;
            }
        }

        // Now poll to find the exact end
        let response = fetch_audit_entries(&self.config, &mut client, low, Some(1000), false)
            .await
            .context(format!("Failed to fetch audit entries at index {low}"))?;
        if response.updates.is_empty() {
            // This should never happen, but we'll handle it just in case
            Err(anyhow::anyhow!("Log end not found at index {low}"))
        } else {
            Ok(low + response.updates.len() as u64)
        }
    }

    /// Submit an auditor tree head signature
    /// SECURITY: Tree head must be committed _before_ signing
    /// or sending to the server. This prevents visible equivocation in case of a crash
    async fn submit_auditor_head(
        &mut self,
        client: &mut KeyTransparencyServiceClient<Channel>,
    ) -> Result<Response<()>, anyhow::Error> {
        let tree_head = self.auditor.sign_head(
            self.transparency_log
                .log_root()
                .context("Tried to submit empty log root")?,
            self.transparency_log.size(),
        );

        let mut request = Request::new(tree_head.clone());
        request.set_timeout(Duration::from_secs(self.config.request_timeout_seconds));

        let response = client
            .set_auditor_head(request)
            .await
            .context(format!("Failed to submit auditor head: {tree_head:?}"))?;
        Ok(response)
    }

    fn hms(&self, seconds: u64) -> String {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;
        format!("{hours:02}:{minutes:02}:{secs:02}")
    }

    /// Run the initial sync to catch up with the log head
    /// This uses concurrent requests to optimize fetch throughput
    pub async fn run_audit(&mut self) -> Result<(), anyhow::Error> {
        // Estimate the end of the log so we can report progress
        let initial_log_end = self
            .estimate_log_end()
            .await
            .context("Failed to estimate log end")?;
        tracing::info!("Estimated log end: {initial_log_end}");

        let transport = self
            .endpoint
            .connect()
            .await
            .context("Failed to connect to server")?;
        let mut client = KeyTransparencyServiceClient::new(transport);

        let batch_size = self.config.default_batch_size;

        // Tracks the last log size that we have reported in performance metrics
        let mut progress = self.transparency_log.size();
        let mut last_reported = std::time::Instant::now();

        // Are we currently in the inital catch-up sync?
        let mut syncing = true;

        let config = self.config.clone();
        let fetch_client = client.clone();
        let fetch_job = |start_index| {
            let mut client: KeyTransparencyServiceClient<Channel> = fetch_client.clone();
            let config = config.clone();
            async move {
                fetch_audit_entries(&config, &mut client, start_index, Some(batch_size), true).await
            }
        };

        let mut queue = VecDeque::new();
        for i in 0..self.config.max_concurrent_requests as u64 {
            let start_index = progress + batch_size * i;
            queue.push_back(tokio::spawn(fetch_job(start_index)))
        }

        loop {
            // Wait for the next job to complete
            let response = queue
                .pop_front()
                .unwrap()
                .await
                .context("Fetch thread panicked")??;
            for update in &response.updates {
                self.transparency_log
                    .apply_update(update.clone())
                    .context(format!("Failed to apply update: {update:?}"))?;
            }

            // Poll interval is a good proxy for progress reporting
            if last_reported.elapsed().as_secs() > self.config.poll_interval_seconds {
                let diff = self.transparency_log.size() - progress;
                progress = self.transparency_log.size();
                // Report progress, don't use newlines
                let elapsed = last_reported.elapsed();
                last_reported = std::time::Instant::now();
                let rate = diff as f64 / elapsed.as_secs_f64();

                if syncing {
                    let percent = (progress as f64 / initial_log_end as f64 * 100.0).round();
                    let remaining =
                        self.hms((initial_log_end.saturating_sub(progress)) / rate as u64);
                    tracing::info!(
                        type = "syncing",
                        rate = rate,
                        percent = percent,
                        remaining = remaining,
                    );
                } else {
                    tracing::info!(
                        type = "auditing",
                        rate = rate,
                    );
                }
            }

            if syncing && !response.more {
                tracing::info!("\nLog sync successful!");
                // Drain the queue
                queue.drain(..).for_each(|job| job.abort());
                syncing = false
            }

            if !syncing {
                self.storage
                    .commit_head(&self.transparency_log)
                    .await
                    .context("Failed to commit log head")?;
                self.submit_auditor_head(&mut client)
                    .await
                    .context("Failed to submit auditor head")?;
                tracing::info!(type="submit-head", index=self.transparency_log.size());
            }

            if !response.more {
                let poll_interval = Duration::from_secs(self.config.poll_interval_seconds);
                tokio::time::sleep(poll_interval).await;
            }

            // Queue the next job
            let fetch_start = self.transparency_log.size() + batch_size * (queue.len() as u64);
            queue.push_back(tokio::spawn(fetch_job(fetch_start)));
        }
    }
}

/// Load configuration from a YAML file
pub fn load_config_from_file(path: &PathBuf) -> Result<ClientConfig, anyhow::Error> {
    let config_content = std::fs::read_to_string(path)?;
    let config: ClientConfig = serde_yaml::from_str(&config_content)?;
    Ok(config)
}

/// Fetch audit entries starting from the given position
/// If retry is true, we will retry on failure, and report intermediate errors
async fn fetch_audit_entries(
    config: &ClientConfig,
    client: &mut KeyTransparencyServiceClient<Channel>,
    start: u64,
    limit: Option<u64>,
    retry: bool, // If true, we will retry on failure, and report the error
) -> Result<AuditResponse, Status> {
    let limit = limit.unwrap_or(config.default_batch_size);

    let mut retries = if retry { config.max_retries } else { 0 };

    loop {
        let mut request = Request::new(AuditRequest { start, limit });
        request.set_timeout(Duration::from_secs(config.request_timeout_seconds));
        let result = client.audit(request).await;
        match result {
            Ok(response) => {
                return Ok(response.into_inner());
            }
            Err(status) => {
                // Patch up the error code to be more useful
                let status = if status.code() == Code::InvalidArgument
                    && status
                        .message()
                        .contains("auditing can not start past end of tree")
                {
                    Status::new(Code::OutOfRange, status.message())
                } else {
                    status
                };

                if retries > 0 {
                    if status.code() != Code::OutOfRange {
                        tracing::warn!(
                            "Failed to fetch audit entries at index {start}, limit {limit}: {:?}, retries remaining: {}",
                            status,
                            retries
                        );
                    }
                    let backoff = 2u64.pow(config.max_retries - retries);
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    retries -= 1;
                } else {
                    return Err(status);
                }
            }
        }
    }
}
