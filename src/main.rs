use std::{path::PathBuf, time::Duration};
use signal_auditor::client::{KeyTransparencyClient, load_config_from_file};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Load configuration from YAML file
    let config_path = PathBuf::from("config.yaml");
    let config = load_config_from_file(&config_path)?;
    
    // Create client
    let mut client = KeyTransparencyClient::new(config).await?;
    
    // Fetch audit entries starting from position 0
    println!("Running audit...");
    client.run_audit().await?;

    let backoff = Duration::from_secs(10);
    loop {
        println!("Running audit...");
        if let Err(e) = client.run_audit().await {
            eprintln!("Error running audit: {e}");
        }
        let backoff = backoff.mul_f32(2.0).min(Duration::from_secs(600));
        println!("backing off for {backoff:?}");
        tokio::time::sleep(backoff).await;
    }
}
