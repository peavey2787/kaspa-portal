use super::*;

#[test]
fn full_suite_has_reference_eighteen_rows() {
    let bits: Vec<u8> = (0..1_024_000)
        .map(|index| ((index * 17 + index / 7) & 1) as u8)
        .collect();
    let results = NistSuite::full(&bits);
    assert_eq!(results.len(), 18);
    assert_eq!(results[0].name, "frequency_monobit");
    assert_eq!(results[17].name, "random_excursions_variant");
}

#[test]
fn invalid_input_is_not_applicable_not_a_statistical_failure() {
    let result = frequency_monobit(b"012");
    assert!(!result.applicable);
    assert!(!result.passed);
    assert!(result.p_value.is_none());
}

#[test]
fn matrix_rank_operates_over_gf2() {
    let bits = b"1000010000100001";
    let result = binary_matrix_rank(bits, 4);
    assert!(result.applicable);
}
