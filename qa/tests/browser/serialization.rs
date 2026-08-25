use kaspa_portal::{
    indexer::{IndexedTransaction, IndexerConfig},
};

#[test]
fn consensus_sized_u64s_serialize_as_decimal_strings() {
    let transaction = IndexedTransaction {
        txid: "abc".into(),
        block_hash: Some("def".into()),
        daa_score: Some(u64::MAX),
        observed_at_ms: u64::MAX,
        addresses: Vec::new(),
        payload: Vec::new(),
        raw: serde_json::Value::Null,
    };
    let value = serde_json::to_value(transaction).unwrap();
    assert_eq!(value["daa_score"], u64::MAX.to_string());
    assert_eq!(value["observed_at_ms"], u64::MAX.to_string());

    let config = IndexerConfig {
        transaction_ttl_ms: u64::MAX,
        ..IndexerConfig::default()
    };
    let value = serde_json::to_value(config).unwrap();
    assert_eq!(value["transaction_ttl_ms"], u64::MAX.to_string());
}
