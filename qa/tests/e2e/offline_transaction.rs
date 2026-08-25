use kaspa_portal::{
    primitives::address::address_to_script_pubkey,
    transaction::{
        builder::{
            GlobalThreadPolicy, GlobalThreadTopupRequest, GlobalThreadWithdrawalRequest,
            PskbGlobalPlan, PskbInputPlan, PskbOutputPlan, PskbPlan, SweepInputPolicy,
        },
        model::SigHashType,
    },
    KaspaPortal,
};
use serde_json::json;

use crate::support::{
    decode_pskb_wire, deterministic_account_xprv, deterministic_wallet, dummy_utxo,
    covenant_network, sign_pskb_for_account, standard_network, RELAY_KSPT_HEX,
};

#[test]
#[ignore = "Pass 2 E2E: run through qa/scripts/run-e2e-rust"]
fn rust_offline_transaction() {
    let standard = standard_network();
    let portal = KaspaPortal::builder()
        .network(standard)
        .build()
        .expect("offline portal");
    let tx = portal.transaction();
    let pskb = tx.pskb();
    let wallet = deterministic_wallet(&portal, 9);
    let imported = deterministic_account_xprv(9);
    let destination = wallet.receive_addresses[1].clone();
    let source_script = address_to_script_pubkey(&wallet.receive_addresses[0]).expect("source spk");
    let destination_script = address_to_script_pubkey(&destination).expect("destination spk");
    let utxo = dummy_utxo(&wallet, 0x11, 0, 500_000_000);

    let planned = tx
        .plan_from_utxos(
            &wallet,
            &destination,
            100_000_000,
            300_000,
            vec![utxo.clone()],
        )
        .expect("offline send planning");
    let reviewed = tx.review(&planned, standard.address_prefix()).expect("review planned transaction");
    assert_eq!(reviewed.input_count, 1);
    assert!(reviewed.output_count >= 1);

    let payload = b"portal-e2e-payload";
    let with_payload = tx.set_payload(&planned, payload).expect("set payload");
    let payload_doc = decode_pskb_wire(&with_payload);
    assert_eq!(payload_doc[0]["global"]["txPayload"], hex::encode(payload));

    // Exercise exact mass analysis and finalization on a PSKB signed through the
    // same compact-KSPT account-sign/merge path used by the funded standard-network E2E.
    let signed_payload_wire = sign_pskb_for_account(&with_payload, &imported, 0x73);
    let analysis = tx
        .analyze_with_fee_rate(&signed_payload_wire, 1)
        .expect("transaction mass/fee analysis");
    assert!(analysis.compute_mass > 0);
    assert!(analysis.estimated_serialized_bytes > 0);
    assert!(analysis.fee_sompi > 0);
    let finalized = tx
        .finalize(&signed_payload_wire)
        .expect("finalize signed offline PSKB");
    assert_eq!(finalized.payload, payload.to_vec());
    assert_eq!(finalized.inputs.len(), 1);
    assert!(finalized.outputs.len() >= 1);

    let lane = tx
        .set_tx_lane(&planned, &"00".repeat(20), 7, 1, payload)
        .expect("set transaction lane");
    let lane_doc = decode_pskb_wire(&lane);
    assert_eq!(lane_doc[0]["global"]["gas"], "7");
    assert_eq!(lane_doc[0]["global"]["txVersion"], 1);
    assert_eq!(lane_doc[0]["global"]["txPayload"], hex::encode(payload));

    let covenant_portal = KaspaPortal::builder()
        .network(covenant_network())
        .build()
        .expect("offline covenant portal");
    let covenant_tx = covenant_portal.transaction();
    let covenant_pskb = covenant_tx.pskb();
    let covenant_wallet = deterministic_wallet(&covenant_portal, 9);
    let covenant_destination = covenant_wallet.receive_addresses[1].clone();
    let covenant_destination_script =
        address_to_script_pubkey(&covenant_destination).expect("covenant destination spk");
    let covenant_utxo = dummy_utxo(&covenant_wallet, 0x12, 0, 500_000_000);
    let covenant_planned = covenant_tx
        .plan_from_utxos(
            &covenant_wallet,
            &covenant_destination,
            100_000_000,
            300_000,
            vec![covenant_utxo],
        )
        .expect("offline covenant send planning");
    let proof = covenant_portal
        .contract()
        .sequence_commit()
        .stealth_proof(&[0x42; 32], 7);
    let proof_wire = covenant_tx
        .apply_sequence_commit_proof(&covenant_planned, &proof)
        .expect("apply sequence-commit proof");
    let proof_doc = decode_pskb_wire(&proof_wire);
    assert_eq!(proof_doc[0]["global"]["txPayload"], hex::encode(&proof.payload));

    let sweep = pskb.plan_sweep(
        std::slice::from_ref(&utxo),
        &source_script,
        &destination_script,
        499_000_000,
        PskbGlobalPlan::standard().with_lock_time(12).with_branch("e2e"),
        &SweepInputPolicy::p2pk(json!({"case": "e2e"})),
    );
    let sweep_wire = pskb.encode(&sweep).expect("encode typed sweep");
    assert_eq!(decode_pskb_wire(&sweep_wire)[0]["outputs"][0]["amount"], "499000000");

    let typed = PskbPlan {
        global: PskbGlobalPlan::standard(),
        inputs: vec![PskbInputPlan::p2pk(
            utxo.clone(),
            &source_script,
            json!({"typed": true}),
        )],
        outputs: vec![PskbOutputPlan::plain(499_000_000, &destination_script)],
    };
    assert!(!pskb.encode(&typed).expect("encode typed PSKB").is_empty());

    let encoded_document = pskb
        .encode_document(json!({
            "global": {"txVersion": 0, "fallbackLockTime": "0"},
            "inputs": [],
            "outputs": []
        }))
        .expect("encode PSKB document");
    let encoded_doc = decode_pskb_wire(&encoded_document);
    assert_eq!(encoded_doc[0]["global"]["txVersion"], 0);
    assert_eq!(encoded_doc[0]["global"]["fallbackLockTime"], "0");
    assert_eq!(encoded_doc[0]["global"]["subnetworkId"], "00".repeat(20));

    let relay = hex::decode(RELAY_KSPT_HEX).expect("relay KSPT vector");
    let signed = tx
        .sign_compact_kspt(&relay, &[1u8; 32], SigHashType::All)
        .expect("KSPT signing");
    assert_eq!(signed.signatures.len(), 1);
    let signed_entropy = tx
        .sign_compact_kspt_with_entropy(&relay, &[1u8; 32], SigHashType::All, &[2u8; 32])
        .expect("KSPT signing with entropy");
    assert_eq!(signed_entropy.signatures.len(), 1);

    let thread = dummy_utxo(&covenant_wallet, 0x21, 2, 100_000_000);
    let covenant_id = [0x42; 32];
    let withdrawal = covenant_pskb
        .plan_global_thread_withdrawal(GlobalThreadWithdrawalRequest {
            thread_utxos: std::slice::from_ref(&thread),
            covenant_script_public_key: &[0xaa, 0xbb],
            destination_script_public_key: &covenant_destination_script,
            redeem_script: &[0x51, 0xac],
            covenant_id: &covenant_id,
            withdrawal: 20_000_000,
            fee: 1_000_000,
            csv_sequence: 9,
            policy: &GlobalThreadPolicy::allowance(123),
        })
        .expect("global-thread withdrawal");
    assert_eq!(withdrawal.user_receives, 19_000_000);
    assert!(!covenant_pskb
        .encode(&withdrawal.plan)
        .expect("withdrawal wire")
        .is_empty());

    let wallet_topup = dummy_utxo(&covenant_wallet, 0x22, 3, 20_000_000);
    let topup = covenant_pskb
        .plan_global_thread_topup(GlobalThreadTopupRequest {
            thread_utxo: thread,
            wallet_utxos: std::slice::from_ref(&wallet_topup),
            covenant_script_public_key: &[0xaa, 0xbb],
            redeem_script: &[0x51, 0xac],
            covenant_id: &covenant_id,
            fee: 1_000_000,
            policy: &GlobalThreadPolicy::spending_limit_topup(11),
        })
        .expect("global-thread topup");
    assert_eq!(topup.wallet_total, 20_000_000);
    assert!(!covenant_pskb
        .encode(&topup.plan)
        .expect("topup wire")
        .is_empty());
}
