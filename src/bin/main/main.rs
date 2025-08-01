use std::{path::PathBuf, time::Duration};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod client;
use client::{KeyTransparencyClient, load_config_from_file};

mod storage;

// TODO - improve error handling, distinguish between fatal and non-fatal errors
// TODO - distinguish between measured and unmeasured config items
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let builder = tracing_subscriber::registry().with(env_filter);

    #[cfg(feature = "stackdriver")]
    builder.with(tracing_stackdriver::layer()).init();

    #[cfg(not(feature = "stackdriver"))]
    builder.with(tracing_subscriber::fmt::layer()).init();

    // Load configuration from YAML file
    let config_path = PathBuf::from("config.yaml");
    let config = load_config_from_file(&config_path)?;

    let mut client = KeyTransparencyClient::new(config).await?;
    let mut backoff = Duration::from_secs(10);
    loop {
        info!("Running audit...");
        if let Err(e) = client.run_audit().await {
            error!("Error running audit: {e:?}");
            info!("backing off for {backoff:?}");
            tokio::time::sleep(backoff).await;
            backoff = backoff.mul_f32(2.0).min(Duration::from_secs(600));
        } else {
            error!("Unexpected audit exit");
        }
    }
}
