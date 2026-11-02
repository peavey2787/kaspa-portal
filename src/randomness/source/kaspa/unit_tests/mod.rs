use super::*;
#[test]
fn buffer_is_bounded() {
    let b = KaspaBlockBuffer::new(2).unwrap();
    for x in 1..=3 {
        b.push(KaspaEntropyEvidence {
            block_hash: [x; 32],
            daa_score: Some(x as u64),
            finalized: true,
        })
        .unwrap()
    }
    let r = b.recent(2).unwrap();
    assert_eq!(r[0].block_hash, [2; 32]);
}
