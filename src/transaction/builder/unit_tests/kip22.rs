use super::*;
use crate::{
    primitives::address::{p2pk_script, KaspaNetwork},
    transaction::{
        interchange::{
            kspt::{is_fully_signed, sign_transaction_multisig_with_entropy, wire::Limits},
            pskt::pipeline::{sign_pskt, verify_for_broadcast},
        },
        model::SigHashType,
    },
    wallet::derivation::kip22::Chain,
};

const SEED: [u8; 64] = [0x52; 64];

fn coin(xonly: [u8; 32]) -> Kip22Coin {
    Kip22Coin {
        utxo: UtxoEntry {
            tx_id: "11".repeat(32),
            index: 0,
            amount: 100_000_000,
            script_public_key: p2sh_script(&kip22::redeem_script_hash(&xonly)).to_vec(),
            block_daa_score: 1,
            covenant_id: None,
        },
        xonly,
    }
}

fn wallet_key() -> [u8; 32] {
    let account = kip22::derive_account_key(&SEED, 0).unwrap();
    kip22::derive_address_key(&account, Chain::Receive, 3)
        .unwrap()
        .public_key_x_only()
        .unwrap()
}

fn spend(xonly: [u8; 32]) -> String {
    let output = PskbOutputPlan::plain(99_000_000, &p2pk_script(&[0x33; 32]));
    encode_spend(&[coin(xonly)], vec![output]).unwrap()
}

fn sign(wire: &str) -> Result<String, String> {
    sign_pskt(
        wire,
        KaspaNetwork::Mainnet,
        Limits::grammar(),
        |transaction| {
            sign_transaction_multisig_with_entropy(
                transaction,
                &[(SEED, true)],
                SigHashType::All,
                None,
                &[0x7a; 32],
            )
            .map_err(|error| format!("{error:?}"))?;
            assert!(is_fully_signed(transaction));
            Ok(())
        },
    )
}

#[test]
fn finalized_spend_pushes_the_signature_then_the_redeem_script() {
    let xonly = wallet_key();
    let verified = verify_for_broadcast(&sign(&spend(xonly)).unwrap(), Limits::grammar()).unwrap();
    let script = verified.inputs()[0]
        .witness()
        .materialize_signature_script()
        .unwrap();
    assert_eq!(script.len(), 1 + 65 + 1 + kip22::REDEEM_SCRIPT_LEN);
    assert_eq!(script[0], 65);
    assert_eq!(script[65], 1);
    assert_eq!(script[66], u8::try_from(kip22::REDEEM_SCRIPT_LEN).unwrap());
    assert_eq!(&script[67..], &kip22::redeem_script(&xonly));
}

#[test]
fn the_unsigned_spend_commits_only_to_the_script_hash_on_chain() {
    let xonly = wallet_key();
    let spent = coin(xonly).utxo.script_public_key;
    assert!(!spent.windows(32).any(|window| window == xonly));
}

#[test]
fn a_seed_without_the_key_cannot_sign() {
    assert!(sign(&spend([0x44; 32])).is_err());
}

#[test]
fn a_coin_paying_another_script_is_rejected() {
    let mut wrong = coin(wallet_key());
    wrong.utxo.script_public_key = p2pk_script(&wrong.xonly).to_vec();
    assert!(encode_spend(&[wrong], Vec::new()).is_err());
}

#[test]
fn a_spend_needs_inputs() {
    assert!(encode_spend(&[], Vec::new()).is_err());
}

fn paid_outputs(wire: &str) -> Vec<(u64, Vec<u8>)> {
    let signed = sign(wire).unwrap();
    verify_for_broadcast(&signed, Limits::grammar())
        .unwrap()
        .outputs()
        .iter()
        .map(|output| (output.amount(), output.script_public_key().to_vec()))
        .collect()
}

#[test]
fn payment_change_returns_to_a_kip22_address() {
    let xonly = wallet_key();
    let change = [0x55; 32];
    let destination = p2pk_script(&[0x33; 32]);
    let wire =
        encode_payment(&[coin(xonly)], &destination, 30_000_000, 1_000_000, &change).unwrap();
    assert_eq!(
        paid_outputs(&wire),
        vec![
            (30_000_000, destination.to_vec()),
            (
                69_000_000,
                p2sh_script(&kip22::redeem_script_hash(&change)).to_vec()
            ),
        ]
    );
}

#[test]
fn dust_change_is_left_to_the_fee() {
    let destination = p2pk_script(&[0x33; 32]);
    let wire = encode_payment(
        &[coin(wallet_key())],
        &destination,
        99_000_000,
        999_999,
        &[0x55; 32],
    )
    .unwrap();
    assert_eq!(paid_outputs(&wire).len(), 1);
}

#[test]
fn a_payment_beyond_the_balance_is_rejected() {
    let destination = p2pk_script(&[0x33; 32]);
    let result = encode_payment(
        &[coin(wallet_key())],
        &destination,
        100_000_000,
        1,
        &[0x55; 32],
    );
    assert!(result.unwrap_err().contains("Insufficient"));
}
