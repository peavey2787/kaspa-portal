use kaspa_portal::{
    indexer::IndexedTransaction,
    network::{health::ConnectionStatus, wrpc::operation::Operation},
    primitives::BlockHash,
    KaspaPortal,
};
use serde_json::json;

use crate::support::{
    deterministic_wallet, live_endpoint, live_genesis_hash, live_network, now_ms,
    INDEXED_FIXTURE_TXID,
};

fn genesis_hash() -> BlockHash {
    let bytes = hex::decode(live_genesis_hash()).expect("selected-network genesis hex");
    let array: [u8; 32] = bytes.try_into().expect("32-byte selected-network genesis hash");
    BlockHash::new(array)
}

#[tokio::test]
#[ignore = "Pass 2 live E2E: requires the configured public standard network"]
async fn rust_live_standard_network_chain() {
    let endpoint = live_endpoint();

    let connected = KaspaPortal::builder()
        .network(live_network())
        .endpoint(endpoint.clone())
        .timeout_ms(15_000)
        .max_retries(3)
        .connect()
        .await
        .expect("builder connect to public selected network");
    assert_eq!(
        connected.network().expect("network").status(),
        ConnectionStatus::Connected
    );

    let portal = KaspaPortal::builder()
        .network(live_network())
        .endpoint(endpoint.clone())
        .build()
        .expect("build selected-network portal");
    let health = portal.connect().await.expect("portal connect to public selected network");
    assert_eq!(health.status, ConnectionStatus::Connected);
    assert_eq!(health.endpoint, endpoint);
    assert!(health.virtual_daa_score.is_some_and(|score| score > 0));

    let network = portal.network().expect("network facade");
    let direct = network.connect().await.expect("network connect");
    assert!(direct.virtual_daa_score.is_some_and(|score| score > 0));
    let current = network.health().await.expect("network health");
    assert!(current.virtual_daa_score.is_some_and(|score| score > 0));
    let reconnected = network.reconnect().await.expect("network reconnect");
    assert_eq!(reconnected.status, ConnectionStatus::Connected);

    let raw = network
        .client()
        .call(Operation::GetBlockDagInfo, &[1, 0])
        .await
        .expect("raw GetBlockDagInfo call");
    assert!(!raw.is_empty());

    let chain = portal.chain().expect("chain facade");
    let score = chain
        .virtual_daa_score()
        .await
        .expect("live virtual DAA score");
    assert!(score.get() > 0);
    let genesis = chain
        .block_raw(&genesis_hash())
        .await
        .expect("fetch selected-network genesis block");
    assert!(!genesis.is_empty());

    let wallet = deterministic_wallet(&portal, 0x51);
    let address = &wallet.receive_addresses[0];
    let single = chain.utxos(address).await.expect("live UTXO query");
    let many = chain
        .utxos_many(&wallet.receive_addresses[..2])
        .await
        .expect("live multi-address UTXO query");
    assert!(many.len() >= single.len());

    let fee = chain.fee_estimate().await.expect("live fee estimate");
    assert!(fee.normal_sompi_per_gram.is_finite());
    assert!(fee.normal_sompi_per_gram >= 0.0);

    // Chain transaction lookup is intentionally backed by the Portal indexer.
    // Exercise that public bridge using a stable transaction identity while
    // the surrounding scenario proves the same Portal is connected to the selected network.
    let payload = b"standard-indexed-payload".to_vec();
    portal
        .indexer()
        .ingest_transaction(IndexedTransaction {
            txid: INDEXED_FIXTURE_TXID.into(),
            block_hash: None,
            daa_score: Some(score.get()),
            observed_at_ms: now_ms(),
            addresses: vec![address.clone()],
            payload: payload.clone(),
            raw: json!({
                "version": 1,
                "inputs": [],
                "outputs": [],
                "lockTime": "0",
                "subnetworkId": "00".repeat(20),
                "gas": "0",
                "payload": hex::encode(&payload)
            }),
        })
        .expect("index stable indexed fixture identity");
    let looked_up = chain
        .transaction(INDEXED_FIXTURE_TXID)
        .expect("chain transaction lookup")
        .expect("indexed transaction");
    assert_eq!(looked_up.txid, INDEXED_FIXTURE_TXID);
    assert_eq!(looked_up.payload, payload);
    assert_eq!(looked_up.version, Some(1));
    assert_eq!(looked_up.gas, Some(0));
    let raw_lookup = chain
        .transaction_raw(INDEXED_FIXTURE_TXID)
        .expect("raw transaction lookup")
        .expect("raw indexed transaction");
    assert_eq!(raw_lookup["version"], 1);

    portal.disconnect().expect("portal disconnect");
    assert_eq!(network.status(), ConnectionStatus::Disconnected);
}
