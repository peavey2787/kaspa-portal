use super::*;
#[test]
fn page_is_bounded() {
    let v = vec![1, 2, 3];
    crate::test_support::assert_err_text(
        &page(
            &v,
            PageRequest {
                offset: 0,
                limit: 3,
            },
            2,
        ),
        "page limit exceeds configured maximum 2",
    );
    let p = page(
        &v,
        PageRequest {
            offset: 1,
            limit: 2,
        },
        2,
    )
    .unwrap();
    assert_eq!(p.items, vec![2, 3]);
}
