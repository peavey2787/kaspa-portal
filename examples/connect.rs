use kaspa_portal::{primitives::NetworkId, KaspaPortal, Result};

fn main() -> Result<()> {
    futures::executor::block_on(async {
        let endpoint = std::env::var("KASPA_PORTAL_ENDPOINT")
            .unwrap_or_else(|_| "wss://127.0.0.1:17110".to_string());
        let portal = KaspaPortal::builder()
            .network(NetworkId::Mainnet)
            .endpoint(endpoint)
            .connect()
            .await?;
        println!("{:?}", portal.network()?.health().await?);
        Ok(())
    })
}
