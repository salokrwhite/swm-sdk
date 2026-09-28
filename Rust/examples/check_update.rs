#![allow(clippy::result_large_err)]

use swm_sdk::{CheckUpdateOptions, Client, ClientOptions};

#[tokio::main]
async fn main() -> swm_sdk::Result<()> {
    let options = ClientOptions::builder()
        .base_url("https://swm-backend.anteasy.com")
        .app_id("00000000-0000-0000-0000-000000000001")
        .release_id("00000000-0000-0000-0000-000000000002")
        .version("1.0.0")
        .root_trust_key_id("root-1")
        .root_trust_public_key("0000000000000000000000000000000000000000000000000000000000000000")
        .build()?;
    let client = Client::new(options)?;
    let update = client.check_update(CheckUpdateOptions::default()).await?;
    println!("update_available={}", update.update_available);
    Ok(())
}
