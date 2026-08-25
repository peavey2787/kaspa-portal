use serde_json::{json, Map, Value};

use super::super::{
    build_if_else_covenant_script, build_p2sh_covenant_sig_script,
    build_p2sh_merkle_claim_sig_script, build_p2sh_oracle_mb_heartbeat_sig_script,
    build_p2sh_private_swap_claim_sig_script, build_p2sh_risc0_claim_sig_script,
    build_p2sh_rollup_refund_sig_script, build_p2sh_zk_claim_sig_script,
};

fn signatures() -> Map<String, Value> {
    let mut signatures = Map::new();
    signatures.insert(
        format!("02{}", "11".repeat(32)),
        json!({"schnorr": "55".repeat(64)}),
    );
    signatures
}

fn with_properties(values: &[(&str, Value)]) -> Map<String, Value> {
    let properties = values
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect();
    let mut input = Map::new();
    input.insert("proprietaries".to_string(), Value::Object(properties));
    input
}

fn route(input: &Map<String, Value>, signatures: &Map<String, Value>) -> Vec<u8> {
    let redeem = [0x63, 0x51, 0x67, 0x00, 0x68];
    build_if_else_covenant_script(input, &redeem, &redeem, signatures, false, false, &None)
        .expect("route")
}

#[test]
fn routing_dispatches_oracle_and_rollup_branches_byte_exactly() {
    let redeem = [0x63, 0x51, 0x67, 0x00, 0x68];
    let empty = Map::new();
    let oracle = with_properties(&[("oracleMbHeartbeat", Value::Bool(true))]);
    assert_eq!(
        route(&oracle, &empty),
        build_p2sh_oracle_mb_heartbeat_sig_script(&redeem).expect("oracle heartbeat"),
    );

    let sigs = signatures();
    let state_refund = with_properties(&[("rollupStateRefund", Value::Bool(true))]);
    let deposit_refund = with_properties(&[("depositHoldingRefund", Value::Bool(true))]);
    let expected = build_p2sh_rollup_refund_sig_script(&redeem, &sigs).expect("refund");
    assert_eq!(route(&state_refund, &sigs), expected);
    assert_eq!(route(&deposit_refund, &sigs), expected);
}

#[test]
fn routing_dispatches_each_proof_family_byte_exactly() {
    let redeem = [0x63, 0x51, 0x67, 0x00, 0x68];
    let sigs = signatures();

    let zk = with_properties(&[
        ("zkProof", Value::String("75".into())),
        (
            "zkPublicInputs",
            Value::Array(vec![Value::String("76".into())]),
        ),
        ("zkVk", Value::String("77".into())),
    ]);
    assert_eq!(
        route(&zk, &sigs),
        build_p2sh_zk_claim_sig_script(&redeem, &sigs, &[0x75], &[vec![0x76]], &[0x77],)
            .expect("zk claim"),
    );

    let fields = json!({
        "claim": "01",
        "controlIndex": "02",
        "controlDigests": "03",
        "journal": "04",
        "imageId": "05",
        "controlId": "06",
        "hashfn": "07"
    });
    let risc0 = with_properties(&[
        ("risc0Seal", Value::String("81".into())),
        ("risc0Fields", fields.clone()),
    ]);
    assert_eq!(
        route(&risc0, &sigs),
        build_p2sh_risc0_claim_sig_script(
            &redeem,
            &sigs,
            &[0x81],
            fields.as_object().expect("fields"),
        )
        .expect("risc0 claim"),
    );

    let private_swap = with_properties(&[("privateSwapClaim", Value::Bool(true))]);
    assert_eq!(
        route(&private_swap, &sigs),
        build_p2sh_private_swap_claim_sig_script(&redeem, &sigs).expect("private swap"),
    );

    let proof_json = json!([{"sibling": "b1".repeat(32), "direction": 0}]).to_string();
    let merkle = with_properties(&[
        ("merkleProof", Value::String(proof_json.clone())),
        ("merkleDestSpk", Value::String("b2".into())),
    ]);
    assert_eq!(
        route(&merkle, &sigs),
        build_p2sh_merkle_claim_sig_script(&redeem, &sigs, &proof_json, &[0xb2])
            .expect("merkle claim"),
    );
}

#[test]
fn fallback_signature_route_requires_either_owner_or_nonbeneficiary_signature() {
    let redeem = [0x51, 0xac];
    let sigs = signatures();
    let actual =
        build_if_else_covenant_script(&Map::new(), &redeem, &redeem, &sigs, false, false, &None)
            .expect("fallback signature route");
    let expected =
        build_p2sh_covenant_sig_script(&redeem, &sigs, false).expect("direct signature route");
    assert_eq!(actual, expected);
}
