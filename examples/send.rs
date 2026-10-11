use kaspa_portal::{primitives::NetworkId, KaspaPortal, Result};

// Native Portal runs its wRPC transport on a Tokio runtime.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let endpoint = match std::env::var("KASPA_PORTAL_ENDPOINT") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("set KASPA_PORTAL_ENDPOINT, KASPA_PORTAL_KPUB and KASPA_PORTAL_DESTINATION");
            return Ok(());
        }
    };
    let kpub = std::env::var("KASPA_PORTAL_KPUB")
        .map_err(|_| kaspa_portal::Error::Config("KASPA_PORTAL_KPUB is required".into()))?;
    let destination = std::env::var("KASPA_PORTAL_DESTINATION")
        .map_err(|_| kaspa_portal::Error::Config("KASPA_PORTAL_DESTINATION is required".into()))?;

    let portal = KaspaPortal::builder()
        .network(NetworkId::Mainnet)
        .endpoint(endpoint)
        .connect()
        .await?;
    let wallet = portal.wallet().import_kpub(&kpub)?;
    let pskb = portal
        .transaction()
        .plan_send(&wallet, &destination, 100_000_000, 10_000)
        .await?;
    println!("{pskb}");
    Ok(())
}
