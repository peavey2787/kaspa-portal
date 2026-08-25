use kaspa_portal::indexer::IndexedTransaction;

#[test]
fn consensus_integers_reject_json_numbers_at_browser_boundaries() {
    for number in ["1", "9007199254740991", "9007199254740992"] {
        let json = format!(r#"{{
            "txid":"abc",
            "block_hash":null,
            "daa_score":{number},
            "observed_at_ms":"1",
            "addresses":[],
            "payload":[],
            "raw":null
        }}"#);
        assert!(serde_json::from_str::<IndexedTransaction>(&json).is_err());
    }
}
