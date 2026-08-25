use kaspa_portal::{
    contract::{crowdfund::CrowdfundScript, shipping_escrow::ShippingEscrowScriptRequest},
    KaspaPortal,
};

#[test]
#[ignore = "Pass 2 E2E: run through qa/scripts/run-e2e-rust"]
fn rust_offline_contracts() {
    let network = crate::support::covenant_network();
    let portal = KaspaPortal::builder()
        .network(network)
        .build()
        .expect("offline portal");
    let contract = portal.contract();

    let script_api = contract.script();
    let covenant = contract.covenant();
    let commit_reveal = contract.commit_reveal();
    let crowdfund = contract.crowdfund();
    let merkle = contract.merkle();
    let oracle = contract.oracle();
    let sequence = contract.sequence_commit();
    let shipping = contract.shipping_escrow();
    let vault = contract.vault();
    let zk = contract.zk();

    let owner = [0x11; 32];
    let second = [0x22; 32];
    let third = [0x33; 32];
    let fourth = [0x44; 32];

    let dms = covenant.dms(&owner, &second, 144);
    assert!(!dms.is_empty());
    assert_eq!(script_api.csv_sequence(&dms).expect("DMS CSV"), Some(144));
    let dms_address = script_api
        .p2sh_address(&dms, network.address_prefix())
        .expect("DMS P2SH address");
    assert!(dms_address.starts_with(&format!("{}:", network.address_prefix())));

    let private_swap = covenant
        .private_swap(&owner, &second, &[0x00, 0x00, 0x51], 5_000, &[0x55; 16])
        .expect("private swap script");
    assert!(!private_swap.is_empty());
    assert_eq!(
        script_api
            .cltv_locktime(&private_swap)
            .expect("private-swap CLTV"),
        Some(5_000)
    );

    let piggy = covenant.piggy_bank(&owner, 25_000_000, 8_000, &[0x66; 8]);
    assert!(!piggy.is_empty());
    assert_eq!(script_api.cltv_locktime(&piggy).expect("piggy CLTV"), Some(8_000));

    let savings = covenant.timelocked_savings(&owner, &second, 12_345);
    assert!(!savings.is_empty());
    assert_eq!(
        script_api.cltv_locktime(&savings).expect("savings CLTV"),
        Some(12_345)
    );

    let payjoin = covenant.payjoin(&owner, &second, 9_999, 2, 2);
    assert!(!payjoin.is_empty());
    assert_eq!(script_api.cltv_locktime(&payjoin).expect("payjoin CLTV"), Some(9_999));

    let commitment = [0x77; 32];
    let commit = commit_reveal.build(&owner, &commitment, 7_777);
    assert!(!commit.is_empty());
    assert_eq!(script_api.cltv_locktime(&commit).expect("commit-reveal CLTV"), Some(7_777));

    let organizer_spk = {
        let mut value = vec![0x00, 0x00, 0x20];
        value.extend_from_slice(&third);
        value.push(0xac);
        value
    };
    let vk_hash = [0x72; 32];
    let campaign_id = crowdfund.campaign_id(100_000_000, 654_321, &vk_hash, &organizer_spk);
    assert_ne!(campaign_id, [0u8; 32]);
    let crowdfund_script = crowdfund
        .redeem_script(CrowdfundScript {
            contributor_pubkey: &owner,
            goal_sompi: 100_000_000,
            locktime_daa: 654_321,
            verifying_key_hash: &vk_hash,
            organizer_output_spk: &organizer_spk,
            salt: &[0x74; 8],
        })
        .expect("crowdfund script");
    assert!(!crowdfund_script.is_empty());
    assert!(crowdfund_script.windows(32).any(|window| window == campaign_id));

    let leaves = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    let root = merkle.root(&leaves);
    let proof = merkle.proof(&leaves, 1);
    assert_ne!(root, [0u8; 32]);
    assert!(!proof.is_empty());

    let heartbeat = oracle.heartbeat_script();
    let heartbeat_sig = oracle.heartbeat_sig_script(&heartbeat);
    let consumer_sig = oracle.consumer_sig_script(&heartbeat);
    assert!(!heartbeat.is_empty());
    assert!(!heartbeat_sig.is_empty());
    assert!(!consumer_sig.is_empty());
    // Both keyless single-path spends push only the revealed redeem script.
    assert_eq!(heartbeat_sig, consumer_sig);

    let stealth_proof = sequence.stealth_proof(&owner, 0x5a);
    assert_eq!(stealth_proof.payload[0], 1);
    assert_eq!(&stealth_proof.payload[1..33], owner.as_slice());
    assert_eq!(stealth_proof.payload[33], 0x5a);

    let shipping_script = shipping
        .build(ShippingEscrowScriptRequest {
            seller_pubkey: &owner,
            deliverer_pubkey: &second,
            buyer_pubkey: &third,
            arbiter_pubkey: &fourth,
            product_sompi: 200_000_000,
            fee_sompi: 1_000_000,
            cltv1_deadline: 50_000,
            cltv2_deadline: 60_000,
            salt: &[0x35; 8],
        })
        .expect("shipping escrow script");
    assert!(!shipping_script.is_empty());

    let tagged = vault.tagged(&owner);
    let split = vault.split(&owner);
    assert!(!tagged.is_empty());
    assert!(!split.is_empty());
    assert_ne!(tagged, split);
    let covenant_id = vault.covenant_id(
        &[0x88; 32],
        3,
        &[(0, 123_000_000, 0, tagged.as_slice()), (1, 45_000_000, 0, split.as_slice())],
    );
    assert_ne!(covenant_id, [0u8; 32]);

    let (proving_key, verifying_key) = zk.trusted_setup().expect("Groth16 trusted setup");
    assert!(!proving_key.is_empty());
    assert!(!verifying_key.is_empty());
    let (proof_bytes, public_input, total) = zk
        .prove_crowdfund(&proving_key, &[10_000_000, 20_000_000, 30_000_000])
        .expect("crowdfund proof");
    assert_eq!(total, 60_000_000);
    assert!(
        zk.verify(&verifying_key, &proof_bytes, &public_input)
            .expect("crowdfund proof verification")
    );
    let mut tampered = proof_bytes.clone();
    tampered[0] ^= 1;
    assert!(!zk.verify(&verifying_key, &tampered, &public_input).unwrap_or(false));
}
