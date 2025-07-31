use std::{path::PathBuf, time::Duration};
use signal_auditor::client::{KeyTransparencyClient, load_config_from_file};

// TODO - improve error handling, distinguish between fatal and non-fatal errors
// TODO - distinguish between measured and unmeasured config items

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Load configuration from YAML file
    let config_path = PathBuf::from("config.yaml");
    let config = load_config_from_file(&config_path)?;
    
    let mut client = KeyTransparencyClient::new(config).await?;
    let mut backoff = Duration::from_secs(10);
    loop {
        println!("Running audit...");
        if let Err(e) = client.run_audit().await {
            eprintln!("Error running audit: {e}");
            println!("backing off for {backoff:?}");
            tokio::time::sleep(backoff).await;
            backoff = backoff.mul_f32(2.0).min(Duration::from_secs(600));
        } else {
            println!("Unexpected audit exit");
        }
    }
}
