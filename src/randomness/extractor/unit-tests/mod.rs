use super::*;
#[test]
fn deterministic() {
    let c = ExtractorConfig::default();
    assert_eq!(
        extract_and_fold(b"abc", b"ctx", c).unwrap(),
        extract_and_fold(b"abc", b"ctx", c).unwrap()
    );
}
#[test]
fn context_separates_outputs() {
    let c = ExtractorConfig::default();
    assert_ne!(
        extract_and_fold(b"abc", b"a", c).unwrap(),
        extract_and_fold(b"abc", b"b", c).unwrap()
    );
}
