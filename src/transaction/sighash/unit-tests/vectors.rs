//! Byte-exact sighash vectors for every mode, payload and sig-op rule
//! (adopted from the KasKold Companion's independent sighash implementation).

use crate::transaction::{
    model::{SigHashType, Transaction},
    sighash::calculate_sighash,
};

struct Input {
    transaction_id: [u8; 32],
    index: u32,
    amount: u64,
    sequence: u64,
    sig_op_count: u8,
    script_version: u16,
    script: &'static [u8],
}

struct Output {
    value: u64,
    script_version: u16,
    script: &'static [u8],
    covenant: Option<(u16, [u8; 32])>,
}

struct Context {
    version: u16,
    subnetwork_id: [u8; 20],
    gas: u64,
    locktime: u64,
    payload: &'static [u8],
}

fn transaction(context: &Context, inputs: &[Input], outputs: &[Output]) -> Transaction {
    let mut tx = Transaction::try_new().expect("transaction storage");
    tx.version = context.version;
    tx.num_inputs = inputs.len();
    tx.num_outputs = outputs.len();
    for (slot, input) in tx.inputs.iter_mut().zip(inputs) {
        slot.previous_outpoint.transaction_id = input.transaction_id;
        slot.previous_outpoint.index = input.index;
        slot.sequence = input.sequence;
        slot.sig_op_count = input.sig_op_count;
        slot.utxo_entry.amount = input.amount;
        let spk = &mut slot.utxo_entry.script_public_key;
        spk.version = input.script_version;
        spk.script[..input.script.len()].copy_from_slice(input.script);
        spk.script_len = input.script.len();
    }
    for (slot, output) in tx.outputs.iter_mut().zip(outputs) {
        slot.value = output.value;
        slot.script_public_key.version = output.script_version;
        slot.script_public_key.script[..output.script.len()].copy_from_slice(output.script);
        slot.script_public_key.script_len = output.script.len();
        if let Some((authorizing_input, id)) = output.covenant {
            slot.has_covenant = true;
            slot.covenant_auth_input = authorizing_input;
            slot.covenant_id = id;
        }
    }
    tx.subnetwork_id = context.subnetwork_id;
    tx.gas = context.gas;
    tx.locktime = context.locktime;
    tx.payload = context.payload.to_vec();
    tx
}

fn sighash(tx: &Transaction, input_index: usize, sighash_type: u8) -> String {
    let mode = SigHashType::from_byte(sighash_type).expect("supported sighash type");
    hex::encode(calculate_sighash(tx, input_index, mode))
}

const fn native(version: u16, locktime: u64, payload: &'static [u8]) -> Context {
    Context {
        version,
        subnetwork_id: [0; 20],
        gas: 0,
        locktime,
        payload,
    }
}

#[test]
fn sighash_all_version_one_vector_is_stable() {
    let tx = transaction(
        &native(1, 6, b""),
        &[Input {
            transaction_id: [0x11; 32],
            index: 2,
            amount: 4,
            sequence: 3,
            sig_op_count: 7,
            script_version: 0,
            script: &[0x51],
        }],
        &[Output {
            value: 5,
            script_version: 0,
            script: &[0x51],
            covenant: None,
        }],
    );
    assert_eq!(
        sighash(&tx, 0, 0x01),
        "6eb878a1f83bcbc18e85e1288adfed5a9dd8d6505cf204575a355f956669e246"
    );
}

#[test]
fn native_non_empty_payload_has_a_byte_exact_vector() {
    let tx = transaction(
        &native(1, 6, b"abc"),
        &[Input {
            transaction_id: [0x11; 32],
            index: 2,
            amount: 4,
            sequence: 3,
            sig_op_count: 0,
            script_version: 0,
            script: &[0x51],
        }],
        &[Output {
            value: 5,
            script_version: 0,
            script: &[0x51],
            covenant: None,
        }],
    );
    assert_eq!(
        sighash(&tx, 0, 0x01),
        "6560ebb918d6082936a3b90ccde07bbab0ea582889c19e1602abdcafb2adbd6f"
    );
}

#[test]
fn version_zero_sig_op_hash_binds_other_inputs_except_anyone_can_pay() {
    let build = |second_sig_ops: u8| {
        transaction(
            &native(0, 11, b""),
            &[
                Input {
                    transaction_id: [0x31; 32],
                    index: 0,
                    amount: 50,
                    sequence: 1,
                    sig_op_count: 1,
                    script_version: 0,
                    script: &[0x51],
                },
                Input {
                    transaction_id: [0x32; 32],
                    index: 1,
                    amount: 30,
                    sequence: 2,
                    sig_op_count: second_sig_ops,
                    script_version: 0,
                    script: &[0x51],
                },
            ],
            &[Output {
                value: 75,
                script_version: 0,
                script: &[0x51],
                covenant: None,
            }],
        )
    };
    let (base, changed) = (build(2), build(3));
    assert_ne!(sighash(&base, 0, 0x01), sighash(&changed, 0, 0x01));
    assert_eq!(sighash(&base, 0, 0x81), sighash(&changed, 0, 0x81));
}

#[derive(Clone, Copy)]
enum Mutation {
    None,
    OtherSequence,
    Payload,
    OtherSigOpCount,
    NonMatchingOutput,
    MatchingOutput,
    OtherPreviousOutput,
    EmptyPayload,
}

fn exact_vector(sighash_type: u8, mutation: Mutation) -> String {
    let inputs = [
        Input {
            transaction_id: if matches!(mutation, Mutation::OtherPreviousOutput) {
                [0x12; 32]
            } else {
                [0x11; 32]
            },
            index: 1,
            amount: 1_000,
            sequence: if matches!(mutation, Mutation::OtherSequence) {
                6
            } else {
                5
            },
            sig_op_count: if matches!(mutation, Mutation::OtherSigOpCount) {
                4
            } else {
                2
            },
            script_version: 0,
            script: &[0x20, 0xaa],
        },
        Input {
            transaction_id: [0x22; 32],
            index: 2,
            amount: 2_000,
            sequence: 9,
            sig_op_count: 3,
            script_version: 1,
            script: &[0x51, 0xac],
        },
    ];
    let outputs = [
        Output {
            value: if matches!(mutation, Mutation::NonMatchingOutput) {
                701
            } else {
                700
            },
            script_version: 0,
            script: &[0x51],
            covenant: None,
        },
        Output {
            value: if matches!(mutation, Mutation::MatchingOutput) {
                1_201
            } else {
                1_200
            },
            script_version: 1,
            script: &[0x52, 0xac],
            covenant: Some((0, [0x33; 32])),
        },
        Output {
            value: 100,
            script_version: 0,
            script: &[0x53],
            covenant: None,
        },
    ];
    let payload: &'static [u8] = match mutation {
        Mutation::Payload => b"abd",
        Mutation::EmptyPayload => b"",
        _ => b"abc",
    };
    let context = Context {
        version: 0,
        subnetwork_id: [0x44; 20],
        gas: 7,
        locktime: 11,
        payload,
    };
    sighash(&transaction(&context, &inputs, &outputs), 1, sighash_type)
}

#[test]
fn every_mode_has_a_byte_exact_vector() {
    for (sighash_type, expected) in [
        (
            0x01,
            "224df12ad73ce66f8cc79f144faea6374ebdc24a7169495cd59d0b85a2694072",
        ),
        (
            0x02,
            "3fd7364f751948c0d2e145f246d743a9b3ac9736b2df2a5e256184dc33aad5c0",
        ),
        (
            0x04,
            "08d9501be22bdbc4e3bc3b85a39e2e33709274265889007d49b99e805eb04892",
        ),
        (
            0x81,
            "b61009b8a8adb253b4fd141fb727704133e00dc950f81e5580c2cb225c2e9f37",
        ),
        (
            0x82,
            "09169a7d19a3d99107209644b39087940ba3f7c397021081b08d766c49522f75",
        ),
        (
            0x84,
            "d3ce2184238d90c89f2f0072153d01355b6cdad8e57cb5c8c81c40f337c5690f",
        ),
    ] {
        assert_eq!(
            exact_vector(sighash_type, Mutation::None),
            expected,
            "{sighash_type:#x}"
        );
    }
}

#[test]
fn each_mode_commits_exactly_the_fields_it_selects() {
    for (sighash_type, mutation, expected) in [
        // Other-input sequence is committed by ALL only.
        (
            0x01,
            Mutation::OtherSequence,
            "115a4d4cad47fcd9d40fba8e464464e921f2006d0051c12bfda4f9693caa882a",
        ),
        (
            0x02,
            Mutation::OtherSequence,
            "3fd7364f751948c0d2e145f246d743a9b3ac9736b2df2a5e256184dc33aad5c0",
        ),
        (
            0x04,
            Mutation::OtherSequence,
            "08d9501be22bdbc4e3bc3b85a39e2e33709274265889007d49b99e805eb04892",
        ),
        (
            0x81,
            Mutation::OtherSequence,
            "b61009b8a8adb253b4fd141fb727704133e00dc950f81e5580c2cb225c2e9f37",
        ),
        // Version-zero sig-op aggregation follows the ANYONECANPAY boundary.
        (
            0x01,
            Mutation::OtherSigOpCount,
            "aa945d72312d7b47af2e62fc34b16b7ba75d261ab5855180dcdc708dc8129471",
        ),
        (
            0x81,
            Mutation::OtherSigOpCount,
            "b61009b8a8adb253b4fd141fb727704133e00dc950f81e5580c2cb225c2e9f37",
        ),
        // ANYONECANPAY excludes the other input's previous outpoint.
        (
            0x01,
            Mutation::OtherPreviousOutput,
            "4b6ef93ba69596b6c8e30396043b87d7e3a388ccd2774755d223e9f4758b568e",
        ),
        (
            0x81,
            Mutation::OtherPreviousOutput,
            "b61009b8a8adb253b4fd141fb727704133e00dc950f81e5580c2cb225c2e9f37",
        ),
        // NONE commits no outputs; SINGLE only output[input_index]; ALL every output.
        (
            0x01,
            Mutation::NonMatchingOutput,
            "3ad156bb54a21b3f62f8a9036a4408042ba8e42cb1fb3e0c5220b1fe3dee4cc5",
        ),
        (
            0x02,
            Mutation::NonMatchingOutput,
            "3fd7364f751948c0d2e145f246d743a9b3ac9736b2df2a5e256184dc33aad5c0",
        ),
        (
            0x04,
            Mutation::NonMatchingOutput,
            "08d9501be22bdbc4e3bc3b85a39e2e33709274265889007d49b99e805eb04892",
        ),
        (
            0x04,
            Mutation::MatchingOutput,
            "6246fc2641678aeca851a7865656a70cbb16e964ed26a78ea30a9e46f7bfa4ec",
        ),
        (
            0x84,
            Mutation::NonMatchingOutput,
            "d3ce2184238d90c89f2f0072153d01355b6cdad8e57cb5c8c81c40f337c5690f",
        ),
        (
            0x84,
            Mutation::MatchingOutput,
            "96109d55ff9dff46c01e7cf8a4ebf535b205b9caab16ad3c39dbe23603dbc383",
        ),
    ] {
        assert_eq!(
            exact_vector(sighash_type, mutation),
            expected,
            "{sighash_type:#x}"
        );
    }
}

#[test]
fn payload_is_byte_exact_for_every_mode_and_non_native_empty_payload() {
    for (sighash_type, expected) in [
        (
            0x01,
            "86f8407d58458c63f27ba9339e791ecd795ba108f6bb41725f2e1901e42cde04",
        ),
        (
            0x02,
            "97cfabcdf55909620073c9a2181d5e68a91cf747fc96115dbf70aab21b55f857",
        ),
        (
            0x04,
            "f966a9a8d05bd527a36552b58c90d650b51e4602ddb8362a734dd496b809cfa8",
        ),
        (
            0x81,
            "3570761a65bebfe297093ff7c3c64294442152f648ee33ba30ed040eee6a7fef",
        ),
        (
            0x82,
            "ce8ccb9e4542988be2c022f9007e36ab030fa09a4817a586a5ee697a4b15fd11",
        ),
        (
            0x84,
            "06a80a151d069073f6bed2f23eb0591c9eb06d656c946c1fc124edd1109d31a5",
        ),
    ] {
        assert_eq!(
            exact_vector(sighash_type, Mutation::Payload),
            expected,
            "{sighash_type:#x}"
        );
    }
    // Only the native subnetwork commits an empty payload as zero.
    assert_eq!(
        exact_vector(0x01, Mutation::EmptyPayload),
        "018ffeecd45ca1b316cac30e3a31e0391b09a5e4f77422777f38f912e07e882a"
    );
}
