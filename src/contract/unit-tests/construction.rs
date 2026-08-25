use crate::contract::{
    covenant::script::{
        build_oracle_v1_covenant_script, build_piggy_bank_script, build_timelocked_savings_script,
        oracle_v1_script_commits_to, ORACLE_V1_SIG_OP_COUNT,
    },
    crowdfund::script::{
        crowdfund_campaign_id, crowdfund_redeem_script, CrowdfundScript,
        CROWDFUND_MAX_SWEEP_FEE_SOMPI, CROWDFUND_SIG_OP_COUNT,
    },
    merkle::script::build_merkle_whitelist_script,
    seq_commit::stealth_proof,
    vault::script::{build_split_vault_script, build_tagged_vault_script, compute_covenant_id},
    zk::cost::{
        groth16_script_units, groth16_sig_op_count, GROTH16_SIG_OP_COUNT, RISC0_SIG_OP_COUNT,
    },
};

#[test]
fn critical_contract_script_builders_and_costs_are_covered() {
    let owner = [0x11; 32];
    let root = [0x22; 32];
    let merkle_zero = build_merkle_whitelist_script(&owner, &root, 0, 100);
    let merkle_three = build_merkle_whitelist_script(&owner, &root, 3, 100);
    assert!(merkle_three.len() > merkle_zero.len());
    assert_eq!(merkle_zero.last(), Some(&0x68));

    let tagged = build_tagged_vault_script(&owner);
    let split = build_split_vault_script(&owner);
    assert!(!tagged.is_empty());
    assert!(split.len() > tagged.len());
    assert_eq!(
        tagged
            .iter()
            .filter(|&&opcode| opcode == crate::contract::script::opcode::OP_CHECKSIGVERIFY)
            .count(),
        1,
        "tagged vault must contain exactly one signature-check opcode",
    );

    assert_eq!(
        RISC0_SIG_OP_COUNT,
        u8::MAX,
        "RISC0-backed contract verification must retain its conservative sig-op cost",
    );

    let beneficiary = [0x33; 32];
    let oracle = [0x44; 32];
    let commitment = [0x55; 32];
    let oracle_script = build_oracle_v1_covenant_script(
        &owner,
        &beneficiary,
        &oracle,
        &commitment,
        123_456,
        &[0x66; 16],
    );
    assert_eq!(oracle_script.first(), Some(&0x10));
    assert!(oracle_v1_script_commits_to(
        &oracle_script,
        &commitment,
        &oracle
    ));
    let mut noncanonical_oracle = oracle_script.clone();
    noncanonical_oracle.insert(noncanonical_oracle.len() - 1, 0x51);
    assert!(
        crate::contract::covenant::script::oracle_v1_attestation_binding(&noncanonical_oracle)
            .is_none()
    );
    assert_eq!(
        oracle_script
            .iter()
            .filter(|&&opcode| opcode == crate::contract::script::opcode::OP_CHECKSIGFROMSTACK)
            .count(),
        1,
        "Oracle-v1 must contain exactly one fixed-message oracle signature check",
    );
    assert_eq!(ORACLE_V1_SIG_OP_COUNT, 2);
    assert!(
        !oracle_script.contains(&crate::contract::script::opcode::OP_TX_INPUT_SPK),
        "oracle role must not have a covenant-spend heartbeat branch"
    );

    let contributor = [0x71; 32];
    let vk_hash = [0x72; 32];
    let mut organizer_spk = vec![0, 0, 0x20];
    organizer_spk.extend_from_slice(&[0x73; 32]);
    organizer_spk.push(crate::contract::script::opcode::OP_CHECKSIG);
    let crowdfund = crowdfund_redeem_script(CrowdfundScript {
        contributor_pubkey: &contributor,
        goal_sompi: 100_000_000,
        locktime_daa: 654_321,
        verifying_key_hash: &vk_hash,
        organizer_output_spk: &organizer_spk,
        salt: &[0x74; 8],
    })
    .expect("crowdfunding script");
    for opcode in [
        crate::contract::script::opcode::OP_ZK_PRECOMPILE,
        crate::contract::script::opcode::OP_TX_INPUT_COUNT,
        crate::contract::script::opcode::OP_TX_INPUT_AMOUNT,
        crate::contract::script::opcode::OP_TX_OUTPUT_COUNT,
        crate::contract::script::opcode::OP_TX_OUTPUT_SPK,
    ] {
        assert!(
            crowdfund.contains(&opcode),
            "crowdfunding script must retain transaction/proof invariant opcode {opcode:#x}"
        );
    }
    assert!(
        crowdfund.contains(&crate::contract::script::opcode::OP_TX_INPUT_SCRIPT_SIG_SUBSTR),
        "Crowdfunding sweep must inspect every input's campaign fingerprint"
    );
    assert!(
        crowdfund.contains(&crate::contract::script::opcode::OP_TX_INPUT_SCRIPT_SIG_LEN),
        "Crowdfunding sweep must locate the canonical redeem-script tail"
    );
    assert!(
        !crowdfund.contains(&crate::contract::script::opcode::OP_CHECKSIGFROMSTACK),
        "Crowdfunding sweep must not contain a wallet/raw-hash signature check"
    );
    let campaign_id = crowdfund_campaign_id(100_000_000, 654_321, &vk_hash, &organizer_spk);
    assert_eq!(
        &crowdfund[crowdfund.len() - 34..crowdfund.len() - 2],
        campaign_id.as_slice()
    );
    assert_ne!(
        campaign_id,
        crowdfund_campaign_id(100_000_001, 654_321, &vk_hash, &organizer_spk)
    );
    assert_ne!(
        campaign_id,
        crowdfund_campaign_id(100_000_000, 654_322, &vk_hash, &organizer_spk)
    );
    let mut other_spk = organizer_spk.clone();
    other_spk[2] ^= 1;
    assert_ne!(
        campaign_id,
        crowdfund_campaign_id(100_000_000, 654_321, &vk_hash, &other_spk)
    );
    const { assert!(CROWDFUND_MAX_SWEEP_FEE_SOMPI > 0) };
    assert_eq!(CROWDFUND_SIG_OP_COUNT, GROTH16_SIG_OP_COUNT);
    assert_eq!(GROTH16_SIG_OP_COUNT, groth16_sig_op_count(1));
    assert!(groth16_script_units(1) > 0);
}

#[test]
fn groth16_sig_op_count_saturates_at_u8_max() {
    assert_eq!(groth16_sig_op_count(44), 253);
    assert_eq!(groth16_sig_op_count(45), u8::MAX);
}

#[test]
fn vault_covenant_identity_is_deterministic_and_binds_funding_output() {
    let owner = [0x11; 32];
    let covenant_script = build_tagged_vault_script(&owner);
    let first = compute_covenant_id(&[1; 32], 1, &[(0, 80_000, 0, covenant_script.as_slice())]);
    let repeated = compute_covenant_id(&[1; 32], 1, &[(0, 80_000, 0, covenant_script.as_slice())]);
    assert_eq!(first, repeated);
    assert_ne!(
        first,
        compute_covenant_id(&[2; 32], 1, &[(0, 80_000, 0, covenant_script.as_slice())]),
        "funding transaction ID must bind the covenant identity",
    );
    assert_ne!(
        first,
        compute_covenant_id(&[1; 32], 1, &[(0, 80_001, 0, covenant_script.as_slice())]),
        "genesis amount must bind the covenant identity",
    );
}

#[test]
fn savings_scripts_cover_unconditional_goal_deadline_and_recovery_layouts() {
    let owner = [0x61u8; 32];
    let recovery = [0x62u8; 32];
    let salt = [0x63u8; 8];

    let unconditional = build_piggy_bank_script(&owner, 0, 0, &salt);
    let goal_only = build_piggy_bank_script(&owner, 50_000_000, 0, &salt);
    let deadline_only = build_piggy_bank_script(&owner, 0, 123_456, &salt);
    let both = build_piggy_bank_script(&owner, 50_000_000, 123_456, &salt);
    assert!(goal_only.len() > unconditional.len());
    assert!(deadline_only.len() > unconditional.len());
    assert!(both.len() >= goal_only.len());
    assert_eq!(&unconditional[1..9], salt.as_slice());
    assert!(deadline_only
        .windows(2)
        .any(|window| window == [0x00, 0x67]));
    assert!(goal_only.windows(2).any(|window| window == [0x00, 0x68]));

    let timelocked = build_timelocked_savings_script(&owner, &recovery, 123_456);
    assert!(timelocked.windows(32).any(|window| window == owner));
    assert!(timelocked.windows(32).any(|window| window == recovery));
    assert_eq!(timelocked.last(), Some(&0x68));
}

#[test]
fn stealth_sequence_commit_proof_is_canonical_contract_data() {
    let proof = stealth_proof(&[0x71u8; 32], 0x72);
    assert_eq!(proof.payload.len(), 34);
    assert_eq!(proof.payload[0], 1);
    assert_eq!(&proof.payload[1..33], &[0x71u8; 32]);
    assert_eq!(proof.payload[33], 0x72);
    assert_eq!(proof.gas, 0);
    assert_eq!(proof.transaction_version, 1);
}
