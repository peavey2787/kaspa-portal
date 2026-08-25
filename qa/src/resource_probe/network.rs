use std::hint::black_box;

use kaspa_portal::KaspaPortal;

pub async fn run(endpoint: &str) -> Result<(), String> {
    let portal = KaspaPortal::builder()
        .network(super::standard_network())
        .endpoint(endpoint)
        .timeout_ms(15_000)
        .max_retries(3)
        .build()
        .map_err(|error| error.to_string())?;
    let network = portal.network().map_err(|error| error.to_string())?;
    let connected = network.connect().await.map_err(|error| error.to_string())?;
    let health = network.health().await.map_err(|error| error.to_string())?;
    let reconnected = network.reconnect().await.map_err(|error| error.to_string())?;
    network.disconnect();
    black_box((
        connected.virtual_daa_score,
        health.virtual_daa_score,
        reconnected.virtual_daa_score,
    ));
    Ok(())
}
