use alloc::{vec, vec::Vec};

use super::{ConsensusInput, ConsensusOutput, ConsensusTransaction, InputEncoding};
use crate::contract::covenant::identity::{
    covenant_id, AuthorizedOutput, CovenantProofError, GenesisOutpoint,
};

const GENESIS: GenesisOutpoint = GenesisOutpoint {
    transaction_id: [0x11; 32],
    index: 3,
};
const OTHER_SCRIPT: [u8; 1] = [0x51];

fn p2sh_script(hash: [u8; 32]) -> Vec<u8> {
    let mut script = vec![0xaa, 0x20];
    script.extend_from_slice(&hash);
    script.push(0x87);
    script
}

fn output(value: u64, script: &[u8], covenant: Option<(u16, [u8; 32])>) -> ConsensusOutput {
    ConsensusOutput {
        value,
        spk_version: 0,
        spk_script: script.to_vec(),
        covenant,
    }
}

fn input(prev_tx_id: [u8; 32], prev_index: u32) -> ConsensusInput {
    ConsensusInput {
        prev_tx_id,
        prev_index,
        sig_script: Vec::new(),
        sequence: 0,
        sig_op_count: 1,
    }
}

fn genesis_transaction(bindings: [Option<(u16, [u8; 32])>; 3]) -> ConsensusTransaction {
    let p2sh = p2sh_script([0x22; 32]);
    ConsensusTransaction {
        tx_version: 1,
        input_encoding: InputEncoding::Compact,
        inputs: vec![
            input([0x99; 32], 0),
            input(GENESIS.transaction_id, GENESIS.index),
        ],
        outputs: vec![
            output(80_000, &p2sh, bindings[0]),
            output(7, &OTHER_SCRIPT, bindings[1]),
            output(5, &OTHER_SCRIPT, bindings[2]),
        ],
        locktime: 0,
        subnetwork_id: [0; 20],
        gas: 0,
        payload: Vec::new(),
        storage_mass: 0,
    }
}

#[test]
fn covenant_genesis_extracts_the_bound_group_and_verifies_it() {
    let p2sh = p2sh_script([0x22; 32]);
    let outputs = [
        AuthorizedOutput {
            index: 0,
            value: 80_000,
            spk_version: 0,
            spk_script: &p2sh,
        },
        AuthorizedOutput {
            index: 2,
            value: 5,
            spk_version: 0,
            spk_script: &OTHER_SCRIPT,
        },
    ];
    let claimed = covenant_id(GENESIS, &outputs);
    let unrelated = Some((0, [0x77; 32]));
    let tx = genesis_transaction([Some((1, claimed)), unrelated, Some((1, claimed))]);
    let genesis = tx.covenant_genesis(&claimed).expect("verified genesis");
    assert_eq!(genesis.covenant_id, claimed);
    assert_eq!(genesis.outpoint, GENESIS);
    assert_eq!(genesis.authorizing_input, 1);
    assert_eq!(genesis.outputs, outputs.to_vec());
}

#[test]
fn covenant_genesis_refuses_inconsistent_groups() {
    let claimed = [0x33; 32];
    let none = genesis_transaction([None, None, None]);
    assert_eq!(
        none.covenant_genesis(&claimed),
        Err(CovenantProofError::NoAuthorizedOutputs)
    );
    let mixed = genesis_transaction([Some((1, claimed)), None, Some((0, claimed))]);
    assert_eq!(
        mixed.covenant_genesis(&claimed),
        Err(CovenantProofError::MixedAuthorizingInputs)
    );
    let missing = genesis_transaction([Some((2, claimed)), None, None]);
    assert_eq!(
        missing.covenant_genesis(&claimed),
        Err(CovenantProofError::NoSuchInput(2))
    );
    let wrong = genesis_transaction([Some((1, claimed)), None, None]);
    assert_eq!(
        wrong.covenant_genesis(&claimed),
        Err(CovenantProofError::IdMismatch)
    );
}
