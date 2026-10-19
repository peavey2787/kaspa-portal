//! Known answers from rusty-kaspa `consensus/core/src/hashing/sighash.rs`
//! (`tests::test_signature_hash`, commit cfafeb4), so Portal's sighash is
//! anchored to the node implementation rather than only to vectors it shares
//! with KasKold. rusty-kaspa's compute-budget mutations have no Portal field:
//! a version-1 sighash commits neither sig-op counts nor compute budgets, so
//! those cases map to `sig_op_count`, and the version-0 compute-budget no-op
//! is omitted.

use super::{sighash, transaction, Context, Input, Output};
use crate::transaction::model::Transaction;

const PREVIOUS_TX: [u8; 32] = [
    0x88, 0x0e, 0xb9, 0x81, 0x9a, 0x31, 0x82, 0x1d, 0x9d, 0x23, 0x99, 0xe2, 0xf3, 0x5e, 0x24, 0x33,
    0xb7, 0x26, 0x37, 0xe3, 0x93, 0xd7, 0x1e, 0xcc, 0x9b, 0x8d, 0x02, 0x50, 0xf4, 0x91, 0x53, 0xc3,
];
const SCRIPT_1: &[u8] = &[
    0x20, 0x83, 0x25, 0x61, 0x3d, 0x2e, 0xea, 0xf7, 0x17, 0x6a, 0xc6, 0xc6, 0x70, 0xb1, 0x3c, 0x00,
    0x43, 0x15, 0x6c, 0x42, 0x74, 0x38, 0xed, 0x72, 0xd7, 0x4b, 0x78, 0x00, 0x86, 0x2a, 0xd8, 0x84,
    0xe8, 0xac,
];
const SCRIPT_2: &[u8] = &[
    0x20, 0xfc, 0xef, 0x4c, 0x10, 0x6c, 0xf1, 0x11, 0x35, 0xbb, 0xd7, 0x0f, 0x02, 0xa7, 0x26, 0xa9,
    0x21, 0x62, 0xd2, 0xfb, 0x8b, 0x22, 0xf0, 0x46, 0x91, 0x26, 0xf8, 0x00, 0x86, 0x2a, 0xd8, 0x84,
    0xe8, 0xac,
];

const ALL: u8 = 0x01;
const NONE: u8 = 0x02;
const SINGLE: u8 = 0x04;
const ANYONE_CAN_PAY: u8 = 0x80;

#[derive(Clone, Copy)]
enum Base {
    Native,
    NativeV1,
    Subnetwork,
}

#[derive(Clone, Copy)]
enum Modify {
    Nothing,
    Output(usize),
    Input(usize),
    SigOpCount(usize),
    AmountSpent(usize),
    PrevScriptPublicKey(usize),
    Sequence(usize),
    Payload,
    Gas,
    SubnetworkId,
}

fn base(kind: Base) -> Transaction {
    let input = |index: u32, amount: u64, script: &'static [u8]| Input {
        transaction_id: PREVIOUS_TX,
        index,
        amount,
        sequence: u64::from(index),
        sig_op_count: 0,
        script_version: 0,
        script,
    };
    let output = |script: &'static [u8]| Output {
        value: 300,
        script_version: 0,
        script,
        covenant: None,
    };
    let (version, subnetwork_id, gas, payload): (u16, [u8; 20], u64, &'static [u8]) = match kind {
        Base::Native => (0, [0; 20], 0, b""),
        Base::NativeV1 => (1, [0; 20], 0, b""),
        Base::Subnetwork => (
            0,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            250,
            &[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        ),
    };
    transaction(
        &Context {
            version,
            subnetwork_id,
            gas,
            locktime: 1_615_462_089_000,
            payload,
        },
        &[
            input(0, 100, SCRIPT_1),
            input(1, 200, SCRIPT_2),
            input(2, 300, SCRIPT_2),
        ],
        &[output(SCRIPT_2), output(SCRIPT_1)],
    )
}

fn modify(tx: &mut Transaction, action: Modify) {
    match action {
        Modify::Nothing => {}
        Modify::Output(i) => tx.outputs[i].value = 100,
        Modify::Input(i) => tx.inputs[i].previous_outpoint.index = 2,
        Modify::SigOpCount(i) => tx.inputs[i].sig_op_count = 123,
        Modify::AmountSpent(i) => tx.inputs[i].utxo_entry.amount = 666,
        Modify::PrevScriptPublicKey(i) => {
            let spk = &mut tx.inputs[i].utxo_entry.script_public_key;
            spk.script[spk.script_len..spk.script_len + 3].copy_from_slice(&[1, 2, 3]);
            spk.script_len += 3;
        }
        Modify::Sequence(i) => tx.inputs[i].sequence = 12345,
        Modify::Payload => tx.payload = alloc::vec![6, 6, 6, 4, 2, 0, 1, 3, 3, 7],
        Modify::Gas => tx.gas = 1234,
        Modify::SubnetworkId => {
            tx.subnetwork_id = [6, 6, 6, 4, 2, 0, 1, 3, 3, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        }
    }
}

#[test]
fn sighash_matches_rusty_kaspa_known_answers() {
    use Base::{Native, NativeV1, Subnetwork};
    #[rustfmt::skip]
    let vectors = [
        ("native-all-0", Native, ALL, 0, Modify::Nothing, "03b7ac6927b2b67100734c3cc313ff8c2e8b3ce3e746d46dd660b706a916b1f5"),
        ("native-all-0-modify-input-1", Native, ALL, 0, Modify::Input(1), "a9f563d86c0ef19ec2e4f483901d202e90150580b6123c3d492e26e7965f488c"),
        ("native-v1-all-0-modify-sigopcount-0", NativeV1, ALL, 0, Modify::SigOpCount(0), "5b2657524be672e019897646b56da3d192b453d78ae5e6e5c07f029a69f5f075"),
        ("native-v1-all-0-modify-sigopcount-1", NativeV1, ALL, 0, Modify::SigOpCount(1), "5b2657524be672e019897646b56da3d192b453d78ae5e6e5c07f029a69f5f075"),
        ("native-all-0-modify-output-1", Native, ALL, 0, Modify::Output(1), "aad2b61bd2405dfcf7294fc2be85f325694f02dda22d0af30381cb50d8295e0a"),
        ("native-all-0-modify-sequence-1", Native, ALL, 0, Modify::Sequence(1), "0818bd0a3703638d4f01014c92cf866a8903cab36df2fa2506dc0d06b94295e8"),
        ("native-all-anyonecanpay-0", Native, ALL | ANYONE_CAN_PAY, 0, Modify::Nothing, "24821e466e53ff8e5fa93257cb17bb06131a48be4ef282e87f59d2bdc9afebc2"),
        ("native-all-anyonecanpay-0-modify-input-0", Native, ALL | ANYONE_CAN_PAY, 0, Modify::Input(0), "d09cb639f335ee69ac71f2ad43fd9e59052d38a7d0638de4cf989346588a7c38"),
        ("native-all-anyonecanpay-0-modify-input-1", Native, ALL | ANYONE_CAN_PAY, 0, Modify::Input(1), "24821e466e53ff8e5fa93257cb17bb06131a48be4ef282e87f59d2bdc9afebc2"),
        ("native-all-anyonecanpay-0-modify-sequence", Native, ALL | ANYONE_CAN_PAY, 0, Modify::Sequence(1), "24821e466e53ff8e5fa93257cb17bb06131a48be4ef282e87f59d2bdc9afebc2"),
        ("native-none-0", Native, NONE, 0, Modify::Nothing, "38ce4bc93cf9116d2e377b33ff8449c665b7b5e2f2e65303c543b9afdaa4bbba"),
        ("native-none-0-modify-output-1", Native, NONE, 0, Modify::Output(1), "38ce4bc93cf9116d2e377b33ff8449c665b7b5e2f2e65303c543b9afdaa4bbba"),
        ("native-none-0-modify-sequence-0", Native, NONE, 0, Modify::Sequence(0), "d9efdd5edaa0d3fd0133ee3ab731d8c20e0a1b9f3c0581601ae2075db1109268"),
        ("native-none-0-modify-sequence-1", Native, NONE, 0, Modify::Sequence(1), "38ce4bc93cf9116d2e377b33ff8449c665b7b5e2f2e65303c543b9afdaa4bbba"),
        ("native-none-anyonecanpay-0", Native, NONE | ANYONE_CAN_PAY, 0, Modify::Nothing, "06aa9f4239491e07bb2b6bda6b0657b921aeae51e193d2c5bf9e81439cfeafa0"),
        ("native-none-anyonecanpay-0-modify-amount-spent", Native, NONE | ANYONE_CAN_PAY, 0, Modify::AmountSpent(0), "f07f45f3634d3ea8c0f2cb676f56e20993edf9be07a83bf0dfdb3debcf1441bf"),
        ("native-none-anyonecanpay-0-modify-script-public-key", Native, NONE | ANYONE_CAN_PAY, 0, Modify::PrevScriptPublicKey(0), "20a525c54dc33b2a61201f05233c086dbe8e06e9515775181ed96550b4f2d714"),
        ("native-single-0", Native, SINGLE, 0, Modify::Nothing, "44a0b407ff7b239d447743dd503f7ad23db5b2ee4d25279bd3dffaf6b474e005"),
        ("native-single-0-modify-output-1", Native, SINGLE, 0, Modify::Output(1), "44a0b407ff7b239d447743dd503f7ad23db5b2ee4d25279bd3dffaf6b474e005"),
        ("native-single-0-modify-sequence-0", Native, SINGLE, 0, Modify::Sequence(0), "83796d22879718eee1165d4aace667bb6778075dab579c32c57be945f466a451"),
        ("native-single-0-modify-sequence-1", Native, SINGLE, 0, Modify::Sequence(1), "44a0b407ff7b239d447743dd503f7ad23db5b2ee4d25279bd3dffaf6b474e005"),
        ("native-single-2-no-corresponding-output", Native, SINGLE, 2, Modify::Nothing, "022ad967192f39d8d5895d243e025ec14cc7a79708c5e364894d4eff3cecb1b0"),
        ("native-single-2-no-corresponding-output-modify-output-1", Native, SINGLE, 2, Modify::Output(1), "022ad967192f39d8d5895d243e025ec14cc7a79708c5e364894d4eff3cecb1b0"),
        ("native-single-anyonecanpay-0", Native, SINGLE | ANYONE_CAN_PAY, 0, Modify::Nothing, "43b20aba775050cf9ba8d5e48fc7ed2dc6c071d23f30382aea58b7c59cfb8ed7"),
        ("native-single-anyonecanpay-2-no-corresponding-output", Native, SINGLE | ANYONE_CAN_PAY, 2, Modify::Nothing, "846689131fb08b77f83af1d3901076732ef09d3f8fdff945be89aa4300562e5f"),
        ("native-all-0-modify-payload", Native, ALL, 0, Modify::Payload, "72ea6c2871e0f44499f1c2b556f265d9424bfea67cca9cb343b4b040ead65525"),
        ("subnetwork-all-0", Subnetwork, ALL, 0, Modify::Nothing, "b2f421c933eb7e1a91f1d9e1efa3f120fe419326c0dbac487752189522550e0c"),
        ("subnetwork-all-modify-payload", Subnetwork, ALL, 0, Modify::Payload, "12ab63b9aea3d58db339245a9b6e9cb6075b2253615ce0fb18104d28de4435a1"),
        ("subnetwork-all-modify-gas", Subnetwork, ALL, 0, Modify::Gas, "2501edfc0068d591160c4bd98646c6e6892cdc051182a8be3ccd6d67f104fd17"),
        ("subnetwork-all-subnetwork-id", Subnetwork, ALL, 0, Modify::SubnetworkId, "a5d1230ede0dfcfd522e04123a7bcd721462fed1d3a87352031a4f6e3c4389b6"),
    ];
    for (name, kind, sighash_type, input_index, action, expected) in vectors {
        let mut tx = base(kind);
        modify(&mut tx, action);
        assert_eq!(sighash(&tx, input_index, sighash_type), expected, "{name}");
    }
}
