mod consensus;
mod covenant_paths;
mod coverage_ratchet;
mod finalization;
mod parser_agreement;
mod schema_rules;

use serde_json::json;

use super::test_support::SIGNER_TEST_LIMITS;
use super::{attach_input_derivation, attach_output_derivation, VerifiedTransaction};
use crate::{
    primitives::address::KaspaNetwork as Network, transaction::interchange::kspt::wire::Derivation,
};

// The vectors below were written against the KasKold signer's capacity.

fn encode_pskt(pskt_hex: &str, network: Network) -> Result<Vec<u8>, String> {
    super::encode_pskt(pskt_hex, network, SIGNER_TEST_LIMITS)
}

fn merge_signed_kspt(original: &str, signed: &[u8], network: Network) -> Result<String, String> {
    super::merge_signed_kspt(original, signed, network, SIGNER_TEST_LIMITS)
}

fn finalize_json(pskt_hex: &str) -> Result<String, String> {
    super::finalize_json(pskt_hex, SIGNER_TEST_LIMITS)
}

fn pskt_verified_signature_counts(pskt_hex: &str, network: Network) -> Result<Vec<u8>, String> {
    super::verified_signature_counts(pskt_hex, network, SIGNER_TEST_LIMITS)
}

fn verify_complete_kspt(data: &[u8]) -> Result<VerifiedTransaction, String> {
    super::verify_complete_kspt(data, SIGNER_TEST_LIMITS)
}

const fn derivation(branch: u8, index: u32) -> Derivation {
    Derivation { branch, index }
}

#[test]
fn derivation_helpers_own_kaskold_proprietary_encoding() {
    let original = test_pskb([0x11; 32], 500);
    let attached = attach_input_derivation(&original, 0, derivation(0, 500)).expect("attach hint");
    let (format, root) = super::test_support::decode(&attached).expect("decode");
    let doc = super::test_support::document(&root, format).expect("document");
    assert_eq!(
        doc["inputs"][0]["proprietaries"]["kassignerDerivation"]["branch"],
        0
    );
    assert_eq!(
        doc["inputs"][0]["proprietaries"]["kassignerDerivation"]["index"],
        "500"
    );

    let attached_output =
        attach_output_derivation(&attached, 0, derivation(1, 700)).expect("attach output hint");
    let (format, root) = super::test_support::decode(&attached_output).expect("decode output hint");
    let doc = super::test_support::document(&root, format).expect("output document");
    assert_eq!(
        doc["outputs"][0]["proprietaries"]["kassignerDerivation"]["branch"],
        1
    );
    assert_eq!(
        doc["outputs"][0]["proprietaries"]["kassignerDerivation"]["index"],
        "700"
    );

    crate::test_support::assert_err_text(
        &attach_input_derivation(&original, 0, derivation(0, 0x8000_0000)),
        "derivation hint needs branch 0 or 1 and a non-hardened index",
    );
    crate::test_support::assert_err_text(
        &attach_input_derivation(&original, 0, derivation(2, 500)),
        "derivation hint needs branch 0 or 1 and a non-hardened index",
    );
    crate::test_support::assert_err_text(
        &attach_output_derivation(&original, 0, derivation(1, 0x8000_0000)),
        "derivation hint needs branch 0 or 1 and a non-hardened index",
    );
}

fn test_pskb(input_key: [u8; 32], _index: u32) -> String {
    let input_script = format!("000020{}ac", hex::encode(input_key));
    let output_script = input_script.clone();
    let document = json!({
        "global": {
            "version": 0,
            "txVersion": 0,
            "inputCount": 1,
            "outputCount": 1,
            "fallbackLockTime": "0",
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": "0",
            "txPayload": ""
        },
        "inputs": [{
            "previousOutpoint": { "transactionId": hex::encode([0x77u8; 32]), "index": 0 },
            "utxoEntry": { "amount": "100000", "scriptPublicKey": input_script },
            "sequence": "0",
            "sigOpCount": 1,
            "sighashType": 1,
            "partialSigs": {},
            "proprietaries": {}
        }],
        "outputs": [{ "amount": "90000", "scriptPublicKey": output_script, "proprietaries": {} }]
    });
    super::test_support::encode(super::test_support::Format::Pskb, &json!([document]))
        .expect("encode PSKB")
}

#[test]
fn toccata_sized_payloads_relay_through_kspt_up_to_the_consensus_ceiling() {
    use super::test_support::{pskb, unsigned_document};
    use crate::transaction::{interchange::kspt::wire::Limits, model::MAX_PAYLOAD_SIZE};

    let relay = |length: usize, limits: Limits| {
        let mut document = unsigned_document(None, 0x11);
        document["global"]["txPayload"] = json!(hex::encode(vec![0xab; length]));
        super::encode_pskt(&pskb(&document), Network::Mainnet, limits)
    };
    let kspt = relay(200_000, Limits::grammar()).expect("200 kB payload");
    let parsed = super::compact::parse(&kspt, Limits::grammar()).expect("parse");
    assert_eq!(parsed.payload, vec![0xab; 200_000]);
    assert!(relay(MAX_PAYLOAD_SIZE, Limits::grammar()).is_ok());
    assert!(relay(MAX_PAYLOAD_SIZE + 1, Limits::grammar())
        .unwrap_err()
        .contains("payload"));
    assert!(relay(769, SIGNER_TEST_LIMITS)
        .unwrap_err()
        .contains("signer capabilities"));
}

#[test]
fn every_compact_trailer_round_trips_through_the_host_codec() {
    use super::compact::{Input, Output, Transaction};
    use crate::transaction::interchange::kspt::wire::{encode_vec, Limits};

    let input = |derivation, ms45| Input {
        tx_id: [0x22; 32],
        index: 7,
        amount: 100_000,
        sequence: 0,
        sig_op_count: 1,
        script_version: 0,
        script: [&[0x20][..], &[0x11; 32], &[0xac]].concat(),
        has_covenant_id: false,
        signatures: Vec::new(),
        redeem: Vec::new(),
        derivation,
        ms45,
        covenant_execution: None,
        specialized_witness: None,
    };
    let output = |derivation, ms45| Output {
        amount: 1_000,
        script_version: 0,
        script: vec![0x51],
        derivation,
        ms45,
        covenant: None,
    };
    let transaction = Transaction {
        flags: 0,
        version: 0,
        locktime: 0,
        subnetwork: [0; 20],
        gas: 0,
        payload: Vec::new(),
        network: 2,
        inputs: vec![input(Some((1, 9)), None), input(None, Some((3, 1, 4)))],
        outputs: vec![output(Some((0, 5)), None), output(None, Some((6, 0, 8)))],
        stealth: Some([0x77; 32]),
    };
    let wire = encode_vec(&transaction, Limits::grammar()).expect("encode");
    let parsed = super::compact::parse(&wire, Limits::grammar()).expect("parse");
    assert_eq!(parsed, transaction);
}

fn plan_input(
    script: Vec<u8>,
    redeem: Vec<u8>,
    signatures: Vec<super::compact::Signature>,
) -> super::compact::Input {
    super::compact::Input {
        tx_id: [0x22; 32],
        index: 7,
        amount: 100_000,
        sequence: 0,
        sig_op_count: 1,
        script_version: 0,
        script,
        has_covenant_id: false,
        signatures,
        redeem,
        derivation: None,
        ms45: None,
        covenant_execution: None,
        specialized_witness: None,
    }
}

fn plan_signature(position: u8, sighash: u8) -> super::compact::Signature {
    super::compact::Signature {
        position,
        sighash,
        bytes: [position; 64],
    }
}

fn p2sh_of(redeem: &[u8]) -> Vec<u8> {
    let mut script = vec![0xaa, 0x20];
    script.extend_from_slice(&crate::primitives::address::script_hash(redeem));
    script.push(0x87);
    script
}

#[test]
fn witness_plan_binds_p2sh_redeem_and_canonical_p2pk() {
    use super::test_support::{multisig, xonly};

    let p2pk = [&[0x20][..], &xonly(0x11), &[0xac]].concat();
    let one = plan_input(p2pk.clone(), Vec::new(), vec![plan_signature(0, 1)]);
    assert!(super::verified::witness_plan(0, &one).is_ok());
    let not_p2pk = plan_input(vec![0x51], Vec::new(), vec![plan_signature(0, 1)]);
    assert!(super::verified::witness_plan(0, &not_p2pk)
        .unwrap_err()
        .contains("not canonical P2PK"));

    let redeem = multisig(&[0x11, 0x12], 1);
    let bound = plan_input(p2sh_of(&redeem), redeem.clone(), vec![plan_signature(1, 1)]);
    assert!(super::verified::witness_plan(0, &bound).is_ok());
    let rebound = plan_input(p2sh_of(&[0x51]), redeem.clone(), vec![plan_signature(1, 1)]);
    assert!(super::verified::witness_plan(0, &rebound)
        .unwrap_err()
        .contains("does not match"));
    let not_p2sh = plan_input(p2pk, redeem, vec![plan_signature(1, 1)]);
    assert!(super::verified::witness_plan(0, &not_p2sh)
        .unwrap_err()
        .contains("not canonical P2SH"));
}

#[test]
fn verified_model_exposes_the_authorized_values() {
    use super::compact::{Output, Transaction};
    use super::test_support::multisig;
    use super::VerifiedWitnessPlan;

    let redeem = multisig(&[0x11, 0x12, 0x13], 1);
    let mut input = plan_input(p2sh_of(&redeem), redeem, vec![plan_signature(2, 0x81)]);
    input.script_version = 3;
    let verified = super::verified::from_compact(Transaction {
        flags: 1,
        version: 0,
        locktime: 0,
        subnetwork: [0; 20],
        gas: 0,
        payload: Vec::new(),
        network: 1,
        inputs: vec![input],
        outputs: vec![Output {
            amount: 5,
            script_version: 4,
            script: vec![0x51],
            derivation: None,
            ms45: None,
            covenant: None,
        }],
        stealth: None,
    })
    .expect("verified model");
    let input = &verified.inputs()[0];
    assert_eq!(input.script_version(), 3);
    assert_eq!(verified.outputs()[0].script_version(), 4);
    let VerifiedWitnessPlan::Multisig { signatures, .. } = input.witness() else {
        panic!("multisig plan");
    };
    assert_eq!(signatures[0].position(), 2);
    assert_eq!(signatures[0].sighash(), 0x81);
}

fn input_fields(
    edit: impl FnOnce(&mut serde_json::Value),
) -> Result<super::relay_fields::InputFields, String> {
    let mut document = super::test_support::unsigned_document(None, 0x11);
    edit(&mut document["inputs"][0]);
    super::relay_fields::InputFields::parse(&document["inputs"][0])
}

#[test]
fn relayed_input_fields_accept_exact_signer_capacities() {
    use crate::transaction::interchange::kspt::wire::{MAX_REDEEM_SIZE, MAX_SCRIPT_SIZE};

    let signatures = |count: usize| {
        (0..count)
            .map(|index| {
                (
                    format!("02{index:064x}"),
                    json!({"schnorr": "00".repeat(64)}),
                )
            })
            .collect::<serde_json::Map<_, _>>()
    };
    assert!(input_fields(|input| input["partialSigs"] = json!(signatures(5))).is_ok());
    assert!(
        input_fields(|input| input["partialSigs"] = json!(signatures(6)))
            .err()
            .unwrap()
            .contains("too many partial signatures")
    );
    assert!(input_fields(|input| input["sigOpCount"] = json!(5)).is_ok());
    assert!(input_fields(|input| input["sigOpCount"] = json!(6))
        .err()
        .unwrap()
        .contains("sigOpCount exceeds signer capabilities"));
    let spk = |length: usize| format!("0000{}", "51".repeat(length));
    assert!(input_fields(
        |input| input["utxoEntry"]["scriptPublicKey"] = json!(spk(MAX_SCRIPT_SIZE))
    )
    .is_ok());
    assert!(input_fields(
        |input| input["utxoEntry"]["scriptPublicKey"] = json!(spk(MAX_SCRIPT_SIZE + 1))
    )
    .err()
    .unwrap()
    .contains("spk too long"));
    let redeem = |length: usize| json!("51".repeat(length));
    assert!(input_fields(|input| input["redeemScript"] = redeem(MAX_REDEEM_SIZE)).is_ok());
    assert!(
        input_fields(|input| input["redeemScript"] = redeem(MAX_REDEEM_SIZE + 1))
            .err()
            .unwrap()
            .contains("redeemScript exceeds")
    );
    assert!(input_fields(|input| {
        input["covenantExecution"] = json!({"suppliedMask": 1, "other": 0});
    })
    .err()
    .unwrap()
    .contains("must contain only suppliedMask and suppliedTrueMask"));
}

#[test]
fn ms45_candidates_merge_only_when_identical_and_paths_stay_soft() {
    use super::relay_fields::{merge_ms45_candidate, parse_soft};

    let mut parsed = None;
    assert_eq!(merge_ms45_candidate(&mut parsed, (1, 0, 2)), Ok(()));
    assert_eq!(parsed, Some((1, 0, 2)));
    assert_eq!(merge_ms45_candidate(&mut parsed, (1, 0, 2)), Ok(()));
    assert!(merge_ms45_candidate(&mut parsed, (1, 1, 2))
        .unwrap_err()
        .contains("conflicting"));
    assert_eq!(parsed, Some((1, 0, 2)));
    assert_eq!(parse_soft("2147483647"), Some(0x7fff_ffff));
    assert_eq!(parse_soft("2147483648"), None);
    assert_eq!(parse_soft("5'"), None);
}

#[test]
fn partial_signature_fields_are_strictly_shaped() {
    use super::relay_fields::{compressed_xonly, decode_signature};

    let key = "11".repeat(32);
    assert_eq!(compressed_xonly(&format!("02{key}")), Some([0x11; 32]));
    assert_eq!(compressed_xonly(&format!("03{key}")), Some([0x11; 32]));
    assert_eq!(compressed_xonly(&format!("04{key}")), None);
    assert_eq!(compressed_xonly(&format!("02{}", "AB".repeat(32))), None);
    assert_eq!(compressed_xonly(&format!("02{key}00")), None);
    let schnorr = "22".repeat(64);
    assert_eq!(
        decode_signature(&json!({"schnorr": schnorr})),
        Ok([0x22; 64])
    );
    for (malformed, expected) in [
        (
            json!({"ecdsa": schnorr}),
            "partial signature object must contain only the schnorr hex string",
        ),
        (
            json!({"schnorr": schnorr, "extra": 1}),
            "partial signature object must contain only the schnorr hex string",
        ),
        (
            json!({"schnorr": 7}),
            "partial signature object must contain only the schnorr hex string",
        ),
        (json!([]), "partial signature value must be an object"),
    ] {
        crate::test_support::assert_err_text(&decode_signature(&malformed), expected);
    }
    assert!(decode_signature(&json!({"schnorr": "22".repeat(63)}))
        .unwrap_err()
        .contains("64 bytes"));
}

#[test]
fn p2pk_partial_signature_requires_a_canonical_p2pk_script_for_its_key() {
    use super::relay_fields::collect_signatures;

    let key = super::test_support::xonly(0x11);
    let signature = json!({format!("02{}", hex::encode(key)): {"schnorr": "22".repeat(64)}});
    let ok = input_fields(|input| input["partialSigs"] = signature.clone()).unwrap();
    assert_eq!(collect_signatures(&ok).unwrap()[0].position, 0);
    // The key appears in the script but behind CHECKSIGVERIFY: not P2PK.
    let verify = input_fields(|input| {
        input["partialSigs"] = signature.clone();
        input["utxoEntry"]["scriptPublicKey"] = json!(format!("000020{}ad", hex::encode(key)));
    })
    .unwrap();
    assert!(collect_signatures(&verify)
        .err()
        .unwrap()
        .contains("canonical P2PK"));
}

#[test]
fn relay_counts_and_output_scripts_accept_exact_limits() {
    use super::test_support::{pskb, unsigned_document};
    use crate::transaction::interchange::kspt::wire::{Limits, MAX_SCRIPT_SIZE};

    let limits = Limits::new(2, 2, 768);
    let with = |inputs: usize, outputs: usize, script: usize| {
        let mut document = unsigned_document(None, 0x11);
        let input = document["inputs"][0].clone();
        let mut output = document["outputs"][0].clone();
        output["scriptPublicKey"] = json!(format!("0000{}", "51".repeat(script)));
        output["amount"] = json!("1");
        document["inputs"] = json!(vec![input; inputs]);
        document["outputs"] = json!(vec![output; outputs]);
        document["global"]["inputCount"] = json!(inputs);
        document["global"]["outputCount"] = json!(outputs);
        super::encode_pskt(&pskb(&document), Network::Mainnet, limits)
    };
    assert!(with(2, 2, MAX_SCRIPT_SIZE).is_ok());
    assert!(with(3, 2, 1).unwrap_err().contains("too many inputs"));
    assert!(with(2, 3, 1).unwrap_err().contains("too many outputs"));
    assert!(with(1, 1, MAX_SCRIPT_SIZE + 1)
        .unwrap_err()
        .contains("script too long"));
}

#[test]
fn public_sole_signature_attachment_returns_the_signed_document() {
    use super::test_support::{decode, pskb, unsigned_document};

    let public_key = [0x02; 33];
    let signed = super::attach_sole_signature(
        &pskb(&unsigned_document(None, 0x11)),
        &public_key,
        &[0x33; 64],
    )
    .expect("sole signature");
    let (_, root) = decode(&signed).expect("signed PSKB");
    assert_eq!(
        root[0]["inputs"][0]["partialSigs"][hex::encode(public_key)]["schnorr"],
        json!("33".repeat(64))
    );
}

#[test]
fn complete_raw_p2pk_and_multisig_kspt_verify() {
    use super::test_support::{multisig, pskb, sign_first_input, unsigned_document};

    let p2pk = sign_first_input(unsigned_document(None, 0x11), &[0x11]);
    let kspt = encode_pskt(&pskb(&p2pk), Network::Mainnet).expect("signed P2PK KSPT");
    let verified = super::verify_complete_kspt(&kspt, SIGNER_TEST_LIMITS).expect("complete");
    assert_eq!(verified.inputs().len(), 1);

    let redeem = multisig(&[0x11, 0x12], 2);
    let partial = sign_first_input(unsigned_document(Some(&redeem), 0x11), &[0x11]);
    let partial_kspt = encode_pskt(&pskb(&partial), Network::Mainnet).expect("partial");
    assert!(
        super::verify_complete_kspt(&partial_kspt, SIGNER_TEST_LIMITS)
            .unwrap_err()
            .contains("not marked fully signed")
    );
    let full = sign_first_input(unsigned_document(Some(&redeem), 0x11), &[0x11, 0x12]);
    let full_kspt = encode_pskt(&pskb(&full), Network::Mainnet).expect("multisig KSPT");
    assert!(super::verify_complete_kspt(&full_kspt, SIGNER_TEST_LIMITS).is_ok());

    // A fully-signed flag over an incomplete witness is refused.
    let mut forged = partial_kspt;
    forged[5] = 1;
    assert!(super::verify_complete_kspt(&forged, SIGNER_TEST_LIMITS)
        .unwrap_err()
        .contains("not cryptographically complete"));
}

fn single_input_transaction(input: super::compact::Input) -> super::compact::Transaction {
    super::compact::Transaction {
        flags: 0,
        version: 0,
        locktime: 0,
        subnetwork: [0; 20],
        gas: 0,
        payload: Vec::new(),
        network: 1,
        inputs: vec![input],
        outputs: Vec::new(),
        stealth: None,
    }
}

#[test]
fn signed_input_without_redeem_is_complete_only_for_canonical_p2pk() {
    let input = plan_input(vec![0x51], Vec::new(), vec![plan_signature(0, 1)]);
    assert_eq!(
        super::compact::verified_complete(&single_input_transaction(input)),
        Ok(false)
    );
}

#[test]
fn specialized_routes_carry_exactly_one_signature() {
    use super::compact::{specialized_signature_count, SpecializedRoute, SpecializedWitness};

    let with = |signatures| {
        let mut input = plan_input(Vec::new(), vec![0x51], signatures);
        input.specialized_witness = Some(SpecializedWitness {
            route: SpecializedRoute::MerkleClaim,
            signature_script: Vec::new(),
            supplied_mask: 0,
            supplied_true_mask: 0,
        });
        specialized_signature_count(&input, 0)
    };
    assert_eq!(with(vec![plan_signature(0, 1)]), Ok(1));
    crate::test_support::assert_err_text(
        &with(Vec::new()),
        "input[0] typed specialized covenant requires exactly one verified signature",
    );
    crate::test_support::assert_err_text(
        &with(vec![plan_signature(0, 1), plan_signature(1, 1)]),
        "input[0] typed specialized covenant requires exactly one verified signature",
    );
}

#[test]
fn specialized_route_detection_recognizes_each_field_and_rejects_untyped_ones() {
    use super::specialized::{detect_route, reject_all_specialized, RouteKind};

    let detect = |fields: serde_json::Value| detect_route(fields.as_object().expect("object"), 0);
    for (field, route) in [
        ("privateSwapClaim", RouteKind::PrivateSwap),
        ("oracleV1Claim", RouteKind::OracleV1),
        ("oracleV1Signature", RouteKind::OracleV1),
        ("commitPartA", RouteKind::CommitReveal),
        ("commitPartB", RouteKind::CommitReveal),
        ("merkleProof", RouteKind::Merkle),
        ("merkleDestSpk", RouteKind::Merkle),
    ] {
        assert_eq!(detect(json!({field: 1})), Ok(Some(route)), "{field}");
    }
    assert_eq!(detect(json!({"stealthTweak": "00"})), Ok(None));
    assert!(detect(json!({"escrowBranch": 1}))
        .unwrap_err()
        .contains("no typed verified witness plan"));
    assert!(detect(json!({"privateSwapClaim": 1, "merkleProof": 1}))
        .unwrap_err()
        .contains("mixes multiple"));

    let global =
        |value: serde_json::Value| reject_all_specialized(Some(&value), "global.proprietaries");
    assert_eq!(global(json!({"note": 1})), Ok(()));
    assert!(global(json!({"merkleProof": 1}))
        .unwrap_err()
        .contains("input-scoped"));
    crate::test_support::assert_err_text(
        &global(json!(7)),
        "global.proprietaries must be an object or null",
    );
    assert_eq!(reject_all_specialized(None, "global.proprietaries"), Ok(()));
}

#[test]
fn private_swap_template_recognition_is_exact() {
    use super::specialized::recognize_private_swap;

    let script = crate::contract::covenant::build_private_swap_script(
        &[0x11; 32],
        &[0x12; 32],
        &[0x20; 34],
        1_000,
        &[0x5a; 16],
    )
    .expect("private swap script");
    assert_eq!(recognize_private_swap(&script), Ok(()));
    let mut trailing = script.clone();
    trailing.push(0x51);
    assert!(recognize_private_swap(&trailing)
        .unwrap_err()
        .contains("not a canonical Private Swap"));
    crate::test_support::assert_err_text(
        &recognize_private_swap(&[0x51]),
        "not a canonical Private Swap script",
    );
}

#[test]
fn merkle_templates_stop_at_the_selector_capacity() {
    use super::specialized::recognize_merkle;
    use crate::contract::merkle::build_merkle_whitelist_script;

    let template = |depth| build_merkle_whitelist_script(&[7; 32], &[8; 32], depth, 100);
    assert_eq!(recognize_merkle(&template(15)).map(|t| t.depth), Ok(15));
    assert!(recognize_merkle(&template(16))
        .err()
        .unwrap()
        .contains("selector capacity"));
}

#[test]
fn merged_signatures_are_idempotent_and_conflicts_are_refused() {
    use super::compact::insert_signature;

    let key = format!("02{}", "11".repeat(32));
    let mut partials = serde_json::Map::new();
    assert_eq!(
        insert_signature(&mut partials, key.clone(), &[1; 64], 0),
        Ok(())
    );
    assert_eq!(
        insert_signature(&mut partials, key.clone(), &[1; 64], 0),
        Ok(())
    );
    assert_eq!(partials.len(), 1);
    assert!(insert_signature(&mut partials, key, &[2; 64], 0)
        .unwrap_err()
        .contains("conflicting signature"));
    assert_eq!(
        partials.values().next().unwrap()["schnorr"],
        json!("01".repeat(64))
    );
}

#[test]
fn pipeline_sighash_matches_the_signer_model_for_the_same_bytes() {
    use super::compact::{sighash_all, Input, Output, Transaction};
    use crate::transaction::{
        interchange::kspt::{
            parse_compact_kspt,
            wire::{encode_vec, Limits},
        },
        model::{SigHashType, Transaction as Model},
        sighash::calculate_sighash,
    };

    let input = |marker: u8| Input {
        tx_id: [marker; 32],
        index: u32::from(marker),
        amount: 100_000 + u64::from(marker),
        sequence: u64::from(marker),
        sig_op_count: 1,
        script_version: 0,
        script: [&[0x20][..], &[marker; 32], &[0xac]].concat(),
        has_covenant_id: false,
        signatures: Vec::new(),
        redeem: Vec::new(),
        derivation: None,
        ms45: None,
        covenant_execution: None,
        specialized_witness: None,
    };
    let output = |value: u64, covenant| Output {
        amount: value,
        script_version: 0,
        script: vec![0x51, value as u8],
        derivation: None,
        ms45: None,
        covenant,
    };
    for version in [0u16, 1] {
        let transaction = Transaction {
            flags: 0,
            version,
            locktime: 9,
            subnetwork: [0x0b; 20],
            gas: 12,
            payload: vec![7, 8, 9],
            network: 1,
            inputs: vec![input(0x31), input(0x32)],
            outputs: vec![output(1_000, Some((1, [0x66; 32]))), output(2_000, None)],
            stealth: None,
        };
        let wire = encode_vec(&transaction, Limits::grammar()).expect("encode");
        let mut model = Model::try_new().expect("model");
        parse_compact_kspt(&wire, &mut model).expect("model parse");
        for index in 0..2 {
            assert_eq!(
                sighash_all(&transaction, index),
                Ok(calculate_sighash(&model, index, SigHashType::All)),
                "version {version} input {index}"
            );
        }
    }
}
