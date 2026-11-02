use super::*;
use crate::indexer::matcher::{MatchRule, Matcher};

#[test]
fn one_transaction_can_match_multiple_rules() {
    let tx = IndexedTransaction {
        txid: "x".into(),
        block_hash: None,
        daa_score: None,
        observed_at_ms: 1,
        addresses: vec!["a".into()],
        payload: b"xyz".to_vec(),
        raw: serde_json::Value::Null,
    };
    let matchers = vec![
        Matcher {
            id: 1,
            rule: MatchRule::Address("a".into()),
        },
        Matcher {
            id: 2,
            rule: MatchRule::PayloadPrefix(b"x".to_vec()),
        },
    ];
    assert_eq!(scan(&tx, &matchers).len(), 2);
}
