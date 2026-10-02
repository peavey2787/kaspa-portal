use crate::self_test::kspt::run_kspt_tests;

#[test]
fn compact_kspt_vectors_pass() {
    let (passed, total) = run_kspt_tests();
    assert_eq!(passed, total);
}
