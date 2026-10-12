use alloc::{vec, vec::Vec};

use crate::{
    contract::covenant::identity::{
        covenant_id, verify_genesis, verify_redeem_script, AuthorizedOutput, CovenantProofError,
        GenesisOutpoint,
    },
    primitives::address::script_hash,
};

const GENESIS: GenesisOutpoint = GenesisOutpoint {
    transaction_id: [0x11; 32],
    index: 3,
};
const OTHER_SCRIPT: [u8; 1] = [0x51];
/// rusty-kaspa cfafeb4 `hashing::covenant_id::covenant_id` over
/// [`two_outputs`] spent from [`GENESIS`].
const TWO_OUTPUT_ID: &str = "a90591d15cc228dc2bb71c76b8dff8f03f7ba162e407f07f8b71db4e2ffa1379";
/// The same, over the first output alone.
const ONE_OUTPUT_ID: &str = "389e161feaf1c5f2c72cf42ad59c9d399dfe8ca029eabed6f509b9315ada7c27";

fn p2sh_script(hash: [u8; 32]) -> Vec<u8> {
    let mut script = vec![0xaa, 0x20];
    script.extend_from_slice(&hash);
    script.push(0x87);
    script
}

fn two_outputs(p2sh: &[u8]) -> [AuthorizedOutput<'_>; 2] {
    [
        AuthorizedOutput {
            index: 0,
            value: 80_000,
            spk_version: 0,
            spk_script: p2sh,
        },
        AuthorizedOutput {
            index: 2,
            value: 5,
            spk_version: 1,
            spk_script: &OTHER_SCRIPT,
        },
    ]
}

fn id(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

#[test]
fn covenant_id_matches_consensus_known_answers() {
    let p2sh = p2sh_script([0x22; 32]);
    let outputs = two_outputs(&p2sh);
    assert_eq!(covenant_id(GENESIS, &outputs), id(TWO_OUTPUT_ID));
    assert_eq!(covenant_id(GENESIS, &outputs[..1]), id(ONE_OUTPUT_ID));
}

#[test]
fn covenant_id_commits_to_every_preimage_field() {
    let p2sh = p2sh_script([0x22; 32]);
    let base = two_outputs(&p2sh);
    let expected = covenant_id(GENESIS, &base);
    let changed_txid = GenesisOutpoint {
        transaction_id: [0x12; 32],
        ..GENESIS
    };
    let changed_index = GenesisOutpoint {
        index: 4,
        ..GENESIS
    };
    assert_ne!(covenant_id(changed_txid, &base), expected);
    assert_ne!(covenant_id(changed_index, &base), expected);
    let longer = [0x51, 0x00];
    let edits: [fn(&mut AuthorizedOutput<'_>); 4] = [
        |output| output.index = 1,
        |output| output.value = 80_001,
        |output| output.spk_version = 1,
        |output| output.spk_script = &[0x51],
    ];
    for edit in edits {
        let mut outputs = base;
        edit(&mut outputs[0]);
        assert_ne!(covenant_id(GENESIS, &outputs), expected);
    }
    let mut outputs = base;
    outputs[1].spk_script = &longer;
    assert_ne!(covenant_id(GENESIS, &outputs), expected);
}

#[test]
fn verify_genesis_accepts_only_the_exact_ordered_preimage() {
    let p2sh = p2sh_script([0x22; 32]);
    let outputs = two_outputs(&p2sh);
    assert_eq!(
        verify_genesis(&id(TWO_OUTPUT_ID), GENESIS, &outputs),
        Ok(())
    );
    assert_eq!(
        verify_genesis(&id(ONE_OUTPUT_ID), GENESIS, &outputs),
        Err(CovenantProofError::IdMismatch)
    );
    assert_eq!(
        verify_genesis(&id(TWO_OUTPUT_ID), GENESIS, &[]),
        Err(CovenantProofError::NoAuthorizedOutputs)
    );
    let reversed = [outputs[1], outputs[0]];
    assert_eq!(
        verify_genesis(&covenant_id(GENESIS, &reversed), GENESIS, &reversed),
        Err(CovenantProofError::OutputsNotOrdered)
    );
    let duplicated = [outputs[0], outputs[0]];
    assert_eq!(
        verify_genesis(&covenant_id(GENESIS, &duplicated), GENESIS, &duplicated),
        Err(CovenantProofError::OutputsNotOrdered)
    );
}

#[test]
fn verify_redeem_script_requires_version_zero_p2sh_of_that_script() {
    let redeem = [0x51, 0x20, 0x77, 0xac];
    let p2sh = p2sh_script(script_hash(&redeem));
    let mut output = two_outputs(&p2sh)[0];
    assert_eq!(verify_redeem_script(&output, &redeem), Ok(()));
    assert_eq!(
        verify_redeem_script(&output, &redeem[..3]),
        Err(CovenantProofError::RedeemScriptMismatch)
    );
    output.spk_version = 1;
    assert_eq!(
        verify_redeem_script(&output, &redeem),
        Err(CovenantProofError::NotPayToScriptHash)
    );
    output.spk_version = 0;
    output.spk_script = &OTHER_SCRIPT;
    assert_eq!(
        verify_redeem_script(&output, &redeem),
        Err(CovenantProofError::NotPayToScriptHash)
    );
}
