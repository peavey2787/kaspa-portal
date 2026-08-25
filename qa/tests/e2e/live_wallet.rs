use kaspa_portal::KaspaPortal;

use crate::support::{deterministic_wallet, live_endpoint, live_network};

#[tokio::test]
#[ignore = "Pass 2 live E2E: requires the configured public standard network"]
async fn rust_live_standard_wallet() {
    let portal = KaspaPortal::builder()
        .network(live_network())
        .endpoint(live_endpoint())
        .connect()
        .await
        .expect("connect public selected network");
    let wallet = deterministic_wallet(&portal, 0x52);

    let utxos = portal.wallet().utxos(&wallet).await.expect("wallet UTXO scan");
    let balance = portal.wallet().balance(&wallet).await.expect("wallet balance");
    let total = utxos.iter().map(|entry| entry.amount).sum::<u64>();
    assert_eq!(balance.total_sompi, total);
}
