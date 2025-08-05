use anyhow::Context;
use clap::Parser;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod client;
use client::{KeyTransparencyClient, load_config_from_file};

mod storage;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,
}

#[cfg(feature = "stackdriver")]
const GCP_ERROR_TYPE: &str =
    "type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent";

macro_rules! gcp_error {
    ($message:expr) => {
        #[cfg(feature = "stackdriver")]
        error!("@type" = GCP_ERROR_TYPE, message = $message,);
        #[cfg(not(feature = "stackdriver"))]
        error!(message = $message);
    };
}

// TODO - improve error handling, distinguish between fatal and non-fatal errors
// TODO - distinguish between measured and unmeasured config items
#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = run(&args.config).await {
        gcp_error!(format!("Error running audit: {e:?}"));
    }
}

async fn run(config_path: &Path) -> Result<(), anyhow::Error> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let builder = tracing_subscriber::registry().with(env_filter);

    #[cfg(feature = "stackdriver")]
    builder.with(tracing_stackdriver::layer()).init();

    #[cfg(not(feature = "stackdriver"))]
    builder.with(tracing_subscriber::fmt::layer()).init();

    // Load configuration from YAML file
    let config = load_config_from_file(config_path).context("Failed to load config")?;

    let mut client = KeyTransparencyClient::new(config).await?;
    let mut backoff = Duration::from_secs(10);
    loop {
        info!("Running audit...");
        if let Err(e) = client.run_audit().await {
            gcp_error!(format!("Error running audit: {e:?}"));
            info!("backing off for {backoff:?}");
            tokio::time::sleep(backoff).await;
            backoff = backoff.mul_f32(2.0).min(Duration::from_secs(600));
        } else {
            gcp_error!("Unexpected audit exit");
        }
    }
}
