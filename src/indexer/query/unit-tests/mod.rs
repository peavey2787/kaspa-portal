use super::*;
#[test]
fn page_is_bounded() {
    let v = vec![1, 2, 3];
    assert!(page(
        &v,
        PageRequest {
            offset: 0,
            limit: 3
        },
        2
    )
    .is_err());
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
