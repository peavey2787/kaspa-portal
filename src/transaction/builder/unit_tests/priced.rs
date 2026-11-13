//! Every standard send and consolidation pays the feerate on its complete
//! mass, including the KIP-9 storage mass of small outputs.

use super::{decode_pskb_wire, utxo, watch_wallet};
use crate::transaction::builder::{
    planning::amounts::storage_mass_estimate,
    standard::{
        create_consolidation_from_utxos, create_send_from_utxos, create_send_selected_from_utxos,
        prepare_send, storage_mass_fee, validate_recipient_amount, PreparedSend, SendPricing,
    },
};

/// One UTXO holding what the funded testnet wallet held when a 0.2 KAS send
/// priced like a 2,300-gram transfer sat unmined at 6 sompi/gram.
const FUNDED_UTXO: u64 = 9_172_200_000;
const SMALL_PAYMENT: u64 = 20_000_000;

fn plain(fee_rate: u64) -> SendPricing<'static> {
    SendPricing {
        payload: &[],
        fee_rate,
    }
}

fn prepared(amount: u64, fee: u64) -> PreparedSend {
    let destination = crate::primitives::address::encode_p2pk_address(&[0x84; 32], "kaspa");
    prepare_send(&watch_wallet(), &destination, amount, fee).expect("prepared send")
}

/// The input and output amounts of an encoded single-transaction PSKB.
struct DecodedPlan {
    inputs: Vec<u64>,
    outputs: Vec<u64>,
}

impl DecodedPlan {
    fn from_wire(wire: &str) -> Self {
        let doc = decode_pskb_wire(wire);
        let amounts = |entries: &serde_json::Value, pointer: &str| {
            entries
                .as_array()
                .expect("entries")
                .iter()
                .map(|entry| {
                    entry
                        .pointer(pointer)
                        .and_then(serde_json::Value::as_str)
                        .and_then(|amount| amount.parse::<u64>().ok())
                        .expect("amount")
                })
                .collect()
        };
        Self {
            inputs: amounts(&doc[0]["inputs"], "/utxoEntry/amount"),
            outputs: amounts(&doc[0]["outputs"], "/amount"),
        }
    }

    fn fee(&self) -> u64 {
        self.inputs.iter().sum::<u64>() - self.outputs.iter().sum::<u64>()
    }

    fn storage_mass(&self) -> u64 {
        let plural = |amounts: &[u64]| {
            amounts
                .iter()
                .map(|&amount| (amount, 1))
                .collect::<Vec<_>>()
        };
        storage_mass_estimate(&plural(&self.inputs), &plural(&self.outputs)).expect("storage mass")
    }

    /// The fee covers the feerate on the storage mass without paying more
    /// than the compute mass of a small standard transaction on top.
    fn assert_priced_at(&self, fee_rate: u64) {
        const SMALL_TRANSACTION_COMPUTE_MASS: u64 = 4_000;
        let storage_fee = fee_rate * self.storage_mass();
        assert!(
            self.fee() >= storage_fee,
            "fee {} < {storage_fee}",
            self.fee()
        );
        assert!(
            self.fee() <= storage_fee + fee_rate * SMALL_TRANSACTION_COMPUTE_MASS,
            "fee {} overpays {storage_fee}",
            self.fee()
        );
    }
}

#[test]
fn send_preparation_rejects_bad_amounts_and_foreign_destinations() {
    let wallet = watch_wallet();
    let destination = crate::primitives::address::encode_p2pk_address(&[0x83; 32], "kaspa");
    crate::test_support::assert_err_text(&validate_recipient_amount(0), "amount must be > 0");
    crate::test_support::assert_err_text(
        &validate_recipient_amount(1),
        "amount too small (1 sompi)",
    );
    crate::test_support::assert_err_text(
        &prepare_send(&wallet, "not-an-address", SMALL_PAYMENT, 1_000_000),
        "Unknown address prefix",
    );
    let testnet_destination =
        crate::primitives::address::encode_p2pk_address(&[0x83; 32], "kaspatest");
    crate::test_support::assert_err_text(
        &prepare_send(&wallet, &testnet_destination, SMALL_PAYMENT, 1_000_000),
        "Address is on the 'kaspatest' network, but this transaction is on 'kaspa'",
    );
    let empty = crate::wallet::account::derivation::WalletData {
        receive_addresses: Vec::new(),
        ..watch_wallet()
    };
    crate::test_support::assert_err_text(
        &prepare_send(&empty, &destination, SMALL_PAYMENT, 1_000_000),
        "Wallet has no receive address",
    );
    crate::test_support::assert_err_text(
        &prepare_send(&wallet, &destination, u64::MAX - 1, 2),
        "Amount plus fee exceeds supported monetary range",
    );
}

#[test]
fn a_small_automatic_send_pays_the_feerate_on_its_storage_mass() {
    for fee_rate in [110, 220] {
        let wire = create_send_from_utxos(
            &watch_wallet(),
            &prepared(SMALL_PAYMENT, 300_000),
            plain(fee_rate),
            vec![utxo(0xb1, 0, FUNDED_UTXO)],
            8,
        )
        .expect("small send");
        let plan = DecodedPlan::from_wire(&wire);
        assert_eq!(plan.outputs[0], SMALL_PAYMENT);
        assert!(
            plan.storage_mass() >= 49_000,
            "a 0.2 KAS output is storage-heavy"
        );
        plan.assert_priced_at(fee_rate);
    }
}

#[test]
fn a_feerate_below_the_standard_minimum_is_priced_at_the_minimum() {
    let wire = create_send_from_utxos(
        &watch_wallet(),
        &prepared(SMALL_PAYMENT, 0),
        plain(1),
        vec![utxo(0xb2, 0, FUNDED_UTXO)],
        8,
    )
    .expect("small send");
    DecodedPlan::from_wire(&wire)
        .assert_priced_at(crate::transaction::mass::MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM);
}

#[test]
fn a_large_send_pays_its_requested_fee_when_that_exceeds_the_mass_fee() {
    let wire = create_send_from_utxos(
        &watch_wallet(),
        &prepared(1_000_000_000, 2_000_000),
        plain(110),
        vec![utxo(0xb3, 0, FUNDED_UTXO)],
        8,
    )
    .expect("large send");
    assert_eq!(DecodedPlan::from_wire(&wire).fee(), 2_000_000);
}

#[test]
fn automatic_sends_spend_the_largest_utxo_that_covers_the_payment() {
    let wire = create_send_from_utxos(
        &watch_wallet(),
        &prepared(1_000_000_000, 0),
        plain(110),
        vec![
            utxo(0xb4, 0, 100_000_000),
            utxo(0xb5, 1, 9_000_000_000),
            utxo(0xb6, 2, 500_000_000),
        ],
        8,
    )
    .expect("automatic send");
    let plan = DecodedPlan::from_wire(&wire);
    assert_eq!(plan.inputs, vec![9_000_000_000]);
    assert_eq!(plan.outputs.len(), 2);
    plan.assert_priced_at(110);
}

#[test]
fn the_input_limit_bounds_automatic_selection() {
    let wallet = watch_wallet();
    let utxos = vec![
        utxo(0xb7, 0, 1_000_000_000),
        utxo(0xb8, 1, 600_000_000),
        utxo(0xb9, 2, 500_000_000),
    ];
    let send = prepared(1_500_000_000, 0);
    crate::test_support::assert_err_text(
        &create_send_from_utxos(&wallet, &send, plain(110), utxos.clone(), 0),
        "UTXO selection limit must be at least 1",
    );
    crate::test_support::assert_err_text(
        &create_send_from_utxos(&wallet, &send, plain(110), utxos.clone(), 1),
        "Insufficient funds within the current 1-UTXO selection limit: have 1000000000 sompi, need at least 1500300000 sompi plus mass fees. Raise the Advanced UTXO limit or choose UTXOs manually.",
    );
    let wire = create_send_from_utxos(&wallet, &send, plain(110), utxos, 2).expect("two inputs");
    assert_eq!(
        DecodedPlan::from_wire(&wire).inputs,
        vec![1_000_000_000, 600_000_000]
    );
}

#[test]
fn a_selected_send_spends_exactly_its_utxos_and_pays_its_mass_fee() {
    let wallet = watch_wallet();
    let send = prepared(SMALL_PAYMENT, 300_000);
    let wire = create_send_selected_from_utxos(
        &wallet,
        &send,
        plain(110),
        vec![utxo(0xba, 0, 1_000_000_000), utxo(0xbb, 1, FUNDED_UTXO)],
    )
    .expect("selected send");
    let plan = DecodedPlan::from_wire(&wire);
    assert_eq!(plan.inputs, vec![1_000_000_000, FUNDED_UTXO]);
    plan.assert_priced_at(110);
    crate::test_support::assert_err_text(
        &create_send_selected_from_utxos(&wallet, &send, plain(110), Vec::new()),
        "No UTXOs provided",
    );
    crate::test_support::assert_err_text(
        &create_send_selected_from_utxos(
            &wallet,
            &send,
            plain(110),
            vec![utxo(0xbc, 0, 20_200_000)],
        ),
        "Selected UTXOs hold 20200000 sompi, which cannot pay 20000000 sompi plus its mass fee",
    );
}

#[test]
fn an_offline_pskb_is_priced_at_the_default_feerate() {
    let wallet = watch_wallet();
    let destination = crate::primitives::address::encode_p2pk_address(&[0x84; 32], "kaspa");
    crate::test_support::assert_err_text(
        &super::super::standard::create_pskb_with_utxos(
            &wallet,
            &destination,
            SMALL_PAYMENT,
            300_000,
            Vec::new(),
        ),
        "No UTXOs provided",
    );
    let wire = super::super::standard::create_pskb_with_utxos(
        &wallet,
        &destination,
        SMALL_PAYMENT,
        300_000,
        vec![utxo(0xbd, 0, FUNDED_UTXO)],
    )
    .expect("offline PSKB");
    let selected = create_send_selected_from_utxos(
        &wallet,
        &prepared(SMALL_PAYMENT, 300_000),
        plain(110),
        vec![utxo(0xbd, 0, FUNDED_UTXO)],
    )
    .expect("selected send");
    assert_eq!(wire, selected);
    DecodedPlan::from_wire(&wire).assert_priced_at(110);
}

#[test]
fn a_consolidation_pays_its_mass_fee_and_never_less_than_requested() {
    let wallet = watch_wallet();
    let utxos = (0u8..6)
        .map(|index| {
            utxo(
                0xc0 + index,
                u32::from(index),
                100_000_000 * (u64::from(index) + 1),
            )
        })
        .collect::<Vec<_>>();
    let consolidate = |requested_fee, fee_rate| {
        DecodedPlan::from_wire(
            &create_consolidation_from_utxos(&wallet, requested_fee, utxos.clone(), fee_rate)
                .expect("consolidation"),
        )
    };
    let priced = consolidate(0, 110);
    assert_eq!(
        priced.inputs,
        vec![
            600_000_000,
            500_000_000,
            400_000_000,
            300_000_000,
            200_000_000
        ]
    );
    assert_eq!(priced.outputs.len(), 1);
    assert!(priced.fee() > 0);
    assert_eq!(consolidate(0, 220).fee(), 2 * priced.fee());
    assert_eq!(consolidate(10_000_000, 110).fee(), 10_000_000);
    crate::test_support::assert_err_text(
        &create_consolidation_from_utxos(&wallet, 0, vec![utxo(0xc6, 0, 30_000_000)], 110),
        "Only 1 UTXO — nothing to consolidate",
    );
    crate::test_support::assert_err_text(
        &create_consolidation_from_utxos(
            &wallet,
            0,
            vec![utxo(0xc7, 0, 200_000), utxo(0xc8, 1, 100_000)],
            110,
        ),
        "Balance too low to cover fee",
    );
}

#[test]
fn the_fee_estimate_honours_the_requested_fee_payload_and_monetary_range() {
    let selected = [utxo(0xc9, 0, 100_000_000)];
    let estimate = |requested_fee, payload_len| {
        storage_mass_fee(
            &selected,
            100_000_000,
            SMALL_PAYMENT,
            requested_fee,
            payload_len,
            &[34, 34],
            110,
        )
        .expect("estimate")
    };
    assert!(estimate(50_000_000, 0) >= 50_000_000);
    assert!(estimate(300_000, 60 * 1024) > estimate(300_000, 0));
    crate::test_support::assert_err_text(
        &storage_mass_fee(
            &[utxo(0xca, 0, u64::MAX)],
            u64::MAX,
            u64::MAX,
            0,
            0,
            &[34, 34],
            110,
        ),
        "Amount plus fee exceeds supported monetary range",
    );
}

#[test]
fn the_fee_estimate_converges_where_tiny_change_storage_mass_dominates() {
    // Sending 0.2 KAS from one 0.4256 KAS UTXO at 1 sompi/gram: each fee step
    // shrinks the change and raises its storage mass; 16 passes used to give
    // up ("did not converge") just short of the storage-dust boundary.
    let total = 42_558_152u64;
    let fee = storage_mass_fee(
        &[utxo(0xcb, 0, total)],
        total,
        SMALL_PAYMENT,
        0,
        0,
        &[34, 34],
        1,
    )
    .expect("fee converges");
    assert!(fee <= total - SMALL_PAYMENT);
}

#[test]
fn a_payload_send_adds_an_input_instead_of_paying_tiny_change_storage_mass() {
    // Largest-first, one input covers the amount but leaves ~0.22 KAS of
    // change whose storage mass costs more than a second input does.
    let wire = create_send_from_utxos(
        &watch_wallet(),
        &prepared(SMALL_PAYMENT, 0),
        SendPricing {
            payload: &[0x5a; 400],
            fee_rate: 1,
        },
        vec![
            utxo(0xcc, 0, 42_558_152),
            utxo(0xcd, 1, 40_000_000),
            utxo(0xce, 2, 30_000_000),
        ],
        8,
    )
    .expect("payload send plans");
    let plan = DecodedPlan::from_wire(&wire);
    assert!(plan.inputs.len() >= 2, "selection should grow the change");
    // The one-input plan would pay ~0.126 KAS (or burn ~0.226 KAS).
    assert!(
        plan.fee() < 5_000_000,
        "fee {} should be far below the tiny-change penalty",
        plan.fee()
    );
}
