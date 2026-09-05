use crate::transaction::builder::{model::PlannedOutput, planning::amounts::storage_mass_estimate};

#[test]
fn consolidation_rejects_empty_and_singleton_sets_before_sorting() {
    assert_eq!(
        super::super::selection::select_for_consolidation(Vec::new(), 5).unwrap_err(),
        "No UTXOs to consolidate"
    );
    assert_eq!(
        super::super::selection::select_for_consolidation(vec![super::utxo(0x11, 0, 10)], 5)
            .unwrap_err(),
        "Only 1 UTXO — nothing to consolidate"
    );
}

#[test]
fn consolidation_keeps_largest_utxos_when_limited() {
    let selected = super::super::selection::select_for_consolidation(
        vec![
            super::utxo(0x11, 0, 10),
            super::utxo(0x22, 1, 40),
            super::utxo(0x33, 2, 20),
            super::utxo(0x44, 3, 30),
        ],
        3,
    )
    .expect("consolidation selection");
    assert_eq!(
        selected
            .iter()
            .map(|entry| entry.amount)
            .collect::<Vec<_>>(),
        vec![40, 30, 20]
    );
}

#[test]
fn smallest_first_sort_is_not_a_noop() {
    let mut utxos = vec![
        super::utxo(0x11, 0, 30),
        super::utxo(0x22, 1, 10),
        super::utxo(0x33, 2, 20),
    ];
    super::super::selection::sort_smallest_first(&mut utxos);
    assert_eq!(
        utxos.iter().map(|entry| entry.amount).collect::<Vec<_>>(),
        vec![10, 20, 30]
    );
}

#[test]
fn multisig_accepts_exactly_three_inputs_and_rejects_four() {
    let destination = PlannedOutput::new(25, vec![0x51]);
    let three = vec![
        super::utxo(0x11, 0, 10),
        super::utxo(0x22, 1, 10),
        super::utxo(0x33, 2, 10),
    ];
    let (plan, change) = super::super::planning::plan_multisig(
        three.clone(),
        destination.clone(),
        5,
        vec![0x52],
        &[0x51],
        1,
    )
    .expect("three inputs are the protocol maximum");
    assert_eq!(change, 0);
    assert_eq!(plan.inputs.len(), 3);
    assert_eq!(plan.outputs.len(), 1);

    let mut four = three;
    four.push(super::utxo(0x44, 3, 10));
    let error = super::super::planning::plan_multisig(four, destination, 5, vec![0x52], &[0x51], 1)
        .unwrap_err();
    assert!(error.contains("limited to 3 inputs"));
}

#[test]
fn multisig_adds_only_positive_non_dust_change() {
    let destination = PlannedOutput::new(20_000_000, vec![0x51]);
    let (plan, change) = super::super::planning::plan_multisig(
        vec![super::utxo(0x11, 0, 40_000_001)],
        destination,
        1,
        vec![0x52],
        &[0x51],
        1,
    )
    .expect("multisig plan");
    assert_eq!(change, 20_000_000);
    assert_eq!(plan.outputs.len(), 2);
    assert_eq!(plan.outputs[1].amount, 20_000_000);
}

#[test]
fn storage_mass_uses_relaxed_harmonic_rule_for_two_by_two_plurality() {
    let mass = storage_mass_estimate(
        &[(90_000_000, 1), (10_000_000, 1)],
        &[(10_000_000, 1), (10_000_000, 1)],
    )
    .expect("storage mass");
    assert_eq!(mass, 88_889);
}

#[test]
fn storage_mass_fee_accounts_for_omitted_dust_change_as_fee() {
    let dust_selected = vec![super::utxo(0x51, 0, 15_000_000)];
    assert_eq!(
        super::super::standard::storage_mass_fee(&dust_selected, 15_000_000, 10_000_000, 0,)
            .expect("dust-change fee"),
        5_000_000
    );

    // This case used to oscillate between a two-output fee and a one-output
    // fee. Once the mass-required fee makes change dust, the change output is
    // omitted and the full 20M input-minus-payment remainder is the actual fee.
    let oscillating_selected = vec![super::utxo(0x52, 0, 30_000_000)];
    assert_eq!(
        super::super::standard::storage_mass_fee(&oscillating_selected, 30_000_000, 10_000_000, 0,)
            .expect("stable dust-boundary fee"),
        20_000_000
    );
}

#[test]
fn storage_mass_fee_converges_for_non_dust_change() {
    let selected = vec![super::utxo(0x53, 0, 100_000_000)];
    assert_eq!(
        super::super::standard::storage_mass_fee(&selected, 100_000_000, 20_000_000, 0,)
            .expect("non-dust-change fee"),
        5_884_120
    );
}
