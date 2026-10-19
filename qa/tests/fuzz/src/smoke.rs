//! Drives every harness with valid seeds and deterministic mutations of them,
//! so the harnesses and their oracles run on stable toolchains in every
//! validation pass; the libFuzzer workflow explores far beyond this.

use kaspa_portal::{
    primitives::address::KaspaNetwork,
    transaction::{
        interchange::{
            kspt::{parse_compact_kspt, serialize_compact_kspt_vec},
            pskt::{
                shared::{PsktParsed, TxInputFormat},
                standard::serialize_pskt_vec,
            },
            qr::{encode_frame, session_id},
        },
        model::{SigHashType, Transaction},
    },
};

const MUTATIONS_PER_HARNESS: usize = 3_000;

/// xorshift64*: deterministic, so a failing case reproduces exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, input: &mut Vec<u8>) {
    let at = rng.below(input.len());
    match rng.below(5) {
        0 if !input.is_empty() => input[at] ^= 1 << rng.below(8),
        1 if !input.is_empty() => input[at] = rng.next() as u8,
        2 => input.insert(at.min(input.len()), rng.next() as u8),
        3 if !input.is_empty() => {
            input.remove(at);
        }
        _ => input.truncate(at),
    }
}

fn drive(harness: fn(&[u8]), seeds: &[Vec<u8>], salt: u64) {
    for seed in seeds {
        harness(seed);
    }
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ salt);
    for _ in 0..MUTATIONS_PER_HARNESS {
        let mut input = seeds[rng.below(seeds.len())].clone();
        for _ in 0..=rng.below(4) {
            mutate(&mut rng, &mut input);
        }
        harness(&input);
    }
}

fn p2pk(byte: u8) -> [u8; 34] {
    let mut script = [byte; 34];
    script[0] = 0x20;
    script[33] = 0xac;
    script
}

fn sample_transaction() -> Transaction {
    let mut tx = Transaction::try_new().expect("transaction storage");
    tx.network = KaspaNetwork::Mainnet;
    tx.num_inputs = 1;
    tx.num_outputs = 1;
    let input = &mut tx.inputs[0];
    input.previous_outpoint.transaction_id = [0x11; 32];
    input.sig_op_count = 1;
    input.sighash_type = SigHashType::All.to_byte();
    input.utxo_entry.amount = 100_000;
    let spk = &mut input.utxo_entry.script_public_key;
    spk.script[..34].copy_from_slice(&p2pk(0x22));
    spk.script_len = 34;
    tx.outputs[0].value = 90_000;
    tx.outputs[0].script_public_key.script[..34].copy_from_slice(&p2pk(0x33));
    tx.outputs[0].script_public_key.script_len = 34;
    tx
}

fn pskt_json(tx: &Transaction) -> Vec<u8> {
    let wire = serialize_pskt_vec(tx, &PsktParsed::empty(), &[], TxInputFormat::PsktSingle)
        .expect("sample PSKT serializes");
    hex::decode(&wire[4..]).expect("PSKT body is hex")
}

fn qr_frame_seed(payload: &[u8]) -> Vec<u8> {
    let mut frame = [0u8; 128];
    let written = encode_frame(&session_id(payload), 1, 3, payload, &mut frame).expect("frame");
    frame[..written].to_vec()
}

fn with_prefix(prefix: u8, body: &[u8]) -> Vec<u8> {
    let mut seed = vec![prefix];
    seed.extend_from_slice(body);
    seed
}

#[test]
fn parsers_and_codecs_survive_mutated_wire_input() {
    let tx = sample_transaction();
    let kspt = serialize_compact_kspt_vec(&tx).expect("sample KSPT serializes");
    let json = pskt_json(&tx);
    let payload: Vec<u8> = (0..=255u8).cycle().take(400).collect();

    drive(super::kspt, &[kspt.clone(), Vec::new()], 1);
    drive(super::signed_transaction, &[kspt], 2);
    let single = with_prefix(0, &json);
    let bundle = with_prefix(1, &[b"[", json.as_slice(), b"]"].concat());
    drive(super::pskt, &[single.clone(), bundle], 3);
    let (wire, _) = super::pskt_wire(&single).expect("PSKT seed wire");
    drive(super::pskb, &[wire], 4);
    drive(super::qr_frame, &[qr_frame_seed(b"fragment")], 5);
    drive(super::qr_session, &[with_prefix(7, &payload)], 6);
    drive(
        super::rpc_response,
        &[vec![0; 16], b"\x01\x00\x00\x00{}".to_vec()],
        7,
    );
}

#[test]
fn text_and_json_inputs_survive_mutation() {
    let address = b"kaspatest:qzkpehfq6c0gua6lwanp8my4hm0saars3px2kw0gpvtwvky5zk0nu7lm5nrty";
    drive(super::address, &[address.to_vec()], 8);
    drive(
        super::script,
        &[vec![0x04, 0x10, 0x27, 0x00, 0x00, 0xb0, 0x75]],
        9,
    );
    drive(super::beacon_proof, &[b"{}".to_vec()], 10);
    drive(super::indexer_transaction, &[b"{}".to_vec()], 11);
}

#[test]
fn seeds_reach_the_round_trip_oracles() {
    let tx = sample_transaction();
    let json = pskt_json(&tx);
    for seed in [
        with_prefix(0, &json),
        with_prefix(1, &[b"[", json.as_slice(), b"]"].concat()),
    ] {
        let (wire, format) = super::pskt_wire(&seed).expect("seed wire");
        assert!(
            super::pskt_canonical(&wire, format).is_some(),
            "PSKT seed is accepted"
        );
    }
    let kspt = serialize_compact_kspt_vec(&tx).expect("sample KSPT serializes");
    let mut parsed = Transaction::try_new().expect("transaction storage");
    assert_eq!(parse_compact_kspt(&kspt, &mut parsed), Ok(()));
}
