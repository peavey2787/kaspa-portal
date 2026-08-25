use super::*;

#[test]
fn duplicate_is_rejected_inside_window() {
    let mut keys = RecentKeys::new(2);
    assert!(keys.observe("a"));
    assert!(!keys.observe("a"));
}

#[test]
fn oldest_key_falls_out_of_bounded_window() {
    let mut keys = RecentKeys::new(2);
    assert!(keys.observe("a"));
    assert!(keys.observe("b"));
    assert!(keys.observe("c"));
    assert!(keys.observe("a"));
}
