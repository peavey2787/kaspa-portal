use super::*;

#[test]
fn utxo_json_keeps_large_values_as_decimal_strings() {
    let value = UtxoEntry {
        tx_id: "11".repeat(32),
        index: 3,
        amount: u64::MAX,
        script_public_key: vec![0x51],
        block_daa_score: u64::MAX - 1,
        covenant_id: None,
    };
    let json = serde_json::to_value(&value).unwrap();
    assert_eq!(json["amount"], u64::MAX.to_string());
    assert_eq!(json["block_daa_score"], (u64::MAX - 1).to_string());
}
