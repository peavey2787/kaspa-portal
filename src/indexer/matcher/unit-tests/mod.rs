use super::*;
use crate::indexer::event::IndexedTransaction;

fn tx() -> IndexedTransaction {
    IndexedTransaction {
        txid: "a".into(),
        block_hash: None,
        daa_score: None,
        observed_at_ms: 0,
        addresses: vec!["kaspa:q".into()],
        payload: b"abc123".to_vec(),
        raw: serde_json::Value::Null,
    }
}

#[test]
fn payload_modes_are_distinct() {
    let transaction = tx();
    assert!(MatchRule::PayloadPrefix(b"abc".to_vec()).matches(&transaction));
    assert!(MatchRule::PayloadContains(b"c12".to_vec()).matches(&transaction));
    assert!(MatchRule::PayloadSuffix(b"123".to_vec()).matches(&transaction));
    assert!(MatchRule::PayloadExact(b"abc123".to_vec()).matches(&transaction));
    assert!(!MatchRule::PayloadExact(b"abc".to_vec()).matches(&transaction));
}

#[test]
fn address_is_exact() {
    assert!(MatchRule::Address("kaspa:q".into()).matches(&tx()));
    assert!(!MatchRule::Address("kaspa:qq".into()).matches(&tx()));
}

#[test]
fn payload_matchers_reject_empty_values() {
    assert!(MatchRule::PayloadSuffix(Vec::new()).validate().is_err());
}
