use super::*;
#[test]
fn rejects_reverse_range() {
    crate::test_support::assert_err_text(
        &DagRange::new(DaaScore::new(2), DaaScore::new(1), 10),
        "DAG range start exceeds end",
    );
}
#[test]
fn walker_is_bounded() {
    let mut w = DagWalker::from_checkpoints(vec![DagCheckpoint {
        daa_score: DaaScore::new(1),
        block_hash: None,
    }]);
    assert_eq!(w.remaining(), 1);
    assert!(w.next().is_some());
    assert_eq!(w.remaining(), 0);
}
