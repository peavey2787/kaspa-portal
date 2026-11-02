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
    vault::script::{build_split_vault_script, build_tagged_vault_script},
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

#[test]
fn template_recognizers_return_exactly_the_built_fields() {
    use crate::contract::{
        commit_reveal::{
            build_commit_reveal_script, commit_reveal_script_fields, CommitRevealFields,
        },
        covenant::{build_private_swap_script, private_swap_script_fields, PrivateSwapFields},
        merkle::{
            build_merkle_whitelist_script, merkle_whitelist_script_fields, MerkleWhitelistFields,
        },
    };

    for locktime in [5u64, 1_000_000] {
        let swap = PrivateSwapFields {
            owner_pubkey: [1; 32],
            claimer_pubkey: [2; 32],
            claimer_output_spk: [&[0x20][..], &[3; 32], &[0xac]].concat(),
            refund_locktime_daa: locktime,
            salt: [4; 16],
        };
        let script = build_private_swap_script(
            &swap.owner_pubkey,
            &swap.claimer_pubkey,
            &swap.claimer_output_spk,
            swap.refund_locktime_daa,
            &swap.salt,
        )
        .unwrap();
        assert_eq!(private_swap_script_fields(&script), Some(swap));
        let mut altered = script.clone();
        *altered.last_mut().unwrap() = 0x51;
        assert_eq!(private_swap_script_fields(&altered), None);
        assert_eq!(
            private_swap_script_fields(&script[..script.len() - 1]),
            None
        );

        let commit = CommitRevealFields {
            owner_pubkey: [5; 32],
            committed_hash: [6; 32],
            locktime_daa: locktime,
        };
        let script =
            build_commit_reveal_script(&commit.owner_pubkey, &commit.committed_hash, locktime);
        assert_eq!(commit_reveal_script_fields(&script), Some(commit));
        let mut altered = script.clone();
        altered.push(0x51);
        assert_eq!(commit_reveal_script_fields(&altered), None);

        for depth in [0u8, 1, 15] {
            let merkle = MerkleWhitelistFields {
                owner_pubkey: [7; 32],
                merkle_root: [8; 32],
                depth,
                locktime_daa: locktime,
            };
            let script = build_merkle_whitelist_script(&[7; 32], &[8; 32], depth, locktime);
            assert_eq!(merkle_whitelist_script_fields(&script), Some(merkle));
            let mut altered = script.clone();
            altered[0] = 0x64;
            assert_eq!(merkle_whitelist_script_fields(&altered), None);
        }
    }
    assert_eq!(private_swap_script_fields(&[]), None);
    assert_eq!(merkle_whitelist_script_fields(&[0x51; 4]), None);
}

/// A recognizer accepts exactly its builder's output: never a tampered,
/// truncated or extended script.
fn assert_recognizes_only_canonical<T: core::fmt::Debug + PartialEq>(
    script: &[u8],
    fields: &T,
    recognize: fn(&[u8]) -> Option<T>,
) {
    assert_eq!(recognize(script).as_ref(), Some(fields));
    let mut altered = script.to_vec();
    *altered.last_mut().unwrap() ^= 0x01;
    assert_eq!(recognize(&altered), None);
    assert_eq!(recognize(&script[..script.len() - 1]), None);
    assert_eq!(recognize(&[script, &[0x51]].concat()), None);
}

#[test]
fn covenant_recognizers_return_exactly_the_built_fields() {
    use crate::contract::covenant::script::*;

    for locktime in [0u64, 7, 1_000_000] {
        let dms = DmsFields {
            owner_pubkey: [1; 32],
            heir_pubkey: [2; 32],
            inactivity_daa: locktime,
        };
        let script = build_dms_csv_script(&dms.owner_pubkey, &dms.heir_pubkey, locktime);
        assert_recognizes_only_canonical(&script, &dms, dms_script_fields);

        let savings = TimelockedSavingsFields {
            wallet1_pubkey: [3; 32],
            wallet2_pubkey: [4; 32],
            locktime_daa: locktime,
        };
        let script = build_timelocked_savings_script(&[3; 32], &[4; 32], locktime);
        assert_recognizes_only_canonical(&script, &savings, timelocked_savings_script_fields);

        let payjoin = PayjoinFields {
            owner_pubkey: [5; 32],
            beneficiary_pubkey: [6; 32],
            locktime_daa: locktime,
            min_inputs: 2,
            min_outputs: 300,
        };
        let script = build_payjoin_covenant_script(&[5; 32], &[6; 32], locktime, 2, 300);
        assert_recognizes_only_canonical(&script, &payjoin, payjoin_script_fields);

        let oracle = OracleV1Fields {
            owner_pubkey: [7; 32],
            beneficiary_pubkey: [8; 32],
            oracle_pubkey: [9; 32],
            message_commitment: [10; 32],
            locktime_daa: locktime,
            salt: [11; 16],
        };
        let script = build_oracle_v1_covenant_script(
            &[7; 32], &[8; 32], &[9; 32], &[10; 32], locktime, &[11; 16],
        );
        assert_recognizes_only_canonical(&script, &oracle, oracle_v1_script_fields);
    }

    for (threshold_sompi, deadline_daa) in [(0, 0), (50_000_000, 0), (0, 123_456), (1, 2)] {
        let piggy = PiggyBankFields {
            owner_pubkey: [12; 32],
            threshold_sompi,
            deadline_daa,
            salt: [13; 8],
        };
        let script = build_piggy_bank_script(&[12; 32], threshold_sompi, deadline_daa, &[13; 8]);
        assert_recognizes_only_canonical(&script, &piggy, piggy_bank_script_fields);
    }

    for (cooldown_daa, start_daa) in [(0, 0), (600, 0), (0, 9_000), (600, 9_000)] {
        let allowance = GlobalAllowanceFields {
            owner_pubkey: [14; 32],
            beneficiary_pubkey: [15; 32],
            max_withdraw_sompi: 25_000_000,
            cooldown_daa,
            start_daa,
            salt: [16; 8],
        };
        let script = build_global_allowance_script(
            &[14; 32],
            &[15; 32],
            25_000_000,
            cooldown_daa,
            start_daa,
            &[16; 8],
        );
        assert_recognizes_only_canonical(&script, &allowance, global_allowance_script_fields);

        let limit = GlobalSpendingLimitFields {
            owner_pubkey: [21; 32],
            max_withdraw_sompi: start_daa,
            cooldown_daa,
            salt: [22; 8],
        };
        let script =
            build_global_spending_limit_script(&[21; 32], start_daa, cooldown_daa, &[22; 8]);
        assert_recognizes_only_canonical(&script, &limit, global_spending_limit_script_fields);
    }

    let p2pk = |key: u8| [&[0x20][..], &[key; 32], &[0xac]].concat();
    let escrow = EscrowFields {
        alice_pubkey: [17; 32],
        bob_pubkey: [18; 32],
        arbiter_pubkey: [19; 32],
        alice_spk: p2pk(17),
        bob_spk: p2pk(18),
        salt: [20; 8],
    };
    let script = build_escrow_script(
        &[17; 32],
        &[18; 32],
        &[19; 32],
        &p2pk(17),
        &p2pk(18),
        &[20; 8],
    );
    assert_recognizes_only_canonical(&script, &escrow, escrow_script_fields);
}

#[test]
fn covenant_recognizers_reject_every_other_family() {
    use crate::contract::covenant::script::*;

    let scripts = [
        build_dms_csv_script(&[1; 32], &[2; 32], 100),
        build_timelocked_savings_script(&[1; 32], &[2; 32], 100),
        build_payjoin_covenant_script(&[1; 32], &[2; 32], 100, 2, 2),
        build_oracle_v1_covenant_script(&[1; 32], &[2; 32], &[3; 32], &[4; 32], 100, &[5; 16]),
        build_piggy_bank_script(&[1; 32], 100, 100, &[5; 8]),
        build_global_allowance_script(&[1; 32], &[2; 32], 100, 100, 100, &[5; 8]),
        build_escrow_script(&[1; 32], &[2; 32], &[3; 32], &[0x51], &[0x52], &[5; 8]),
        build_global_spending_limit_script(&[1; 32], 100, 100, &[5; 8]),
    ];
    let recognized = |script: &[u8]| {
        [
            dms_script_fields(script).is_some(),
            timelocked_savings_script_fields(script).is_some(),
            payjoin_script_fields(script).is_some(),
            oracle_v1_script_fields(script).is_some(),
            piggy_bank_script_fields(script).is_some(),
            global_allowance_script_fields(script).is_some(),
            escrow_script_fields(script).is_some(),
            global_spending_limit_script_fields(script).is_some(),
        ]
    };
    for (family, script) in scripts.iter().enumerate() {
        let expected: [bool; 8] = core::array::from_fn(|index| index == family);
        assert_eq!(recognized(script), expected, "family {family}");
    }
    assert_eq!(recognized(&[]), [false; 8]);
}

#[test]
fn commit_reveal_reveal_reads_the_preimage_and_checks_the_commitment() {
    use crate::contract::{
        commit_reveal::{build_commit_reveal_script, read_commit_reveal_reveal},
        script::push_data,
    };
    use crate::primitives::hash::blake2b_256;

    let (part_a, part_b) = (b"salt0001".as_slice(), b"hello".as_slice());
    let committed = blake2b_256(&[part_a, part_b].concat());
    let redeem = build_commit_reveal_script(&[5; 32], &committed, 1_000);
    let reveal_script = |redeem: &[u8], selector: u8| {
        let mut script = Vec::new();
        push_data(&mut script, part_a);
        push_data(&mut script, part_b);
        push_data(&mut script, &[9; 65]);
        script.push(selector);
        push_data(&mut script, redeem);
        script
    };

    let reveal = read_commit_reveal_reveal(&reveal_script(&redeem, 0x00)).unwrap();
    assert_eq!(reveal.preimage, b"salt0001hello");
    assert_eq!(reveal.fields.committed_hash, committed);
    assert!(reveal.matches());

    let other = build_commit_reveal_script(&[5; 32], &[6; 32], 1_000);
    assert!(!read_commit_reveal_reveal(&reveal_script(&other, 0x00))
        .unwrap()
        .matches());
    assert_eq!(
        read_commit_reveal_reveal(&reveal_script(&redeem, 0x51)),
        None
    );
    assert_eq!(
        read_commit_reveal_reveal(&reveal_script(&[0x51], 0x00)),
        None
    );
    let script = reveal_script(&redeem, 0x00);
    assert_eq!(read_commit_reveal_reveal(&script[..script.len() - 1]), None);
}
