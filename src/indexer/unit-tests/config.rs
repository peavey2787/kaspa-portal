use super::*;

#[test]
fn mode_shortcuts_have_unambiguous_retention() {
    assert!(IndexingMode::All.retains_transactions());
    assert!(IndexingMode::All.retains_matches());
    assert!(IndexingMode::All.retains_blocks());

    assert!(IndexingMode::Transactions.retains_transaction(true));
    assert!(IndexingMode::Transactions.retains_transaction(false));
    assert!(!IndexingMode::Transactions.retains_matches());

    assert!(IndexingMode::Matches.retains_transaction(true));
    assert!(!IndexingMode::Matches.retains_transaction(false));
    assert!(IndexingMode::Matches.retains_matches());
    assert!(!IndexingMode::Matches.retains_blocks());
}

#[test]
fn custom_mode_composes_storage_classes() {
    let mode = IndexingMode::Custom {
        transactions: false,
        matches: true,
        blocks: true,
    };
    assert!(!mode.retains_transaction(false));
    assert!(mode.retains_transaction(true));
    assert!(mode.retains_matches());
    assert!(mode.retains_blocks());
}

#[test]
fn dedupe_window_is_bounded() {
    let config = IndexerConfig {
        dedupe_window: 0,
        ..IndexerConfig::default()
    };
    assert!(config.validate().is_err());
}
