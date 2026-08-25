use std::{env, fs, path::PathBuf};

use kaspa_portal::{
    chain::utxo::UtxoEntry,
    contract::{crowdfund::CrowdfundScript, shipping_escrow::ShippingEscrowScriptRequest},
    indexer::{IndexedBlock, IndexedTransaction, IndexerApi, IndexerConfig},
    primitives::{address::address_to_script_pubkey, NetworkId},
    randomness::{
        beacon::BeaconRequest,
        extractor::ExtractorConfig,
        source::kaspa::KaspaEntropyEvidence,
        vrf::VrfSecretKey,
    },
    transaction::{
        interchange::{
            kspt::{
                is_fully_signed, parse_compact_kspt, serialize_compact_kspt_vec,
                sign_transaction_account_multi_addr_with_entropy,
            },
            pskt::{merge_signed_kspt_into_pskb, relay_pskb_as_kspt_hex_for_network},
        },
        model::{SigHashType, Transaction},
    },
    wallet::key::xpub::{
        derive_account_raw_kpub_payload, derive_and_serialize_kpub,
        derive_and_serialize_multisig_kpub, derive_and_serialize_xprv,
        import_xprv_with_metadata, ImportedAccountXprv, KPUB_MAX_LEN, XPRV_MAX_LEN,
        XPUB_PAYLOAD_LEN,
    },
    KaspaPortal,
};
use serde_json::json;

const RELAY_KSPT_HEX: &str = "4b53505401000000010000000100000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111010000006400000000000000000000000000000001000022204444444444444444444444444444444444444444444444444444444444444444ac0000005a00000000000000000022205555555555555555555555555555555555555555555555555555555555555555ac4e01";

fn deterministic_kpub(seed_byte: u8) -> String {
    let seed = [seed_byte; 64];
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = derive_and_serialize_kpub(&seed, &mut encoded).expect("derive deterministic kpub");
    std::str::from_utf8(&encoded[..len]).expect("kpub UTF-8").to_owned()
}

fn deterministic_multisig_kpub(seed_byte: u8) -> String {
    let seed = [seed_byte; 64];
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = derive_and_serialize_multisig_kpub(&seed, &mut encoded).expect("derive deterministic multisig kpub");
    std::str::from_utf8(&encoded[..len]).expect("multisig kpub UTF-8").to_owned()
}

fn deterministic_raw_kpub(seed_byte: u8) -> [u8; XPUB_PAYLOAD_LEN] {
    let seed = [seed_byte; 64];
    let mut raw = [0u8; XPUB_PAYLOAD_LEN];
    derive_account_raw_kpub_payload(&seed, &mut raw).expect("derive raw kpub");
    raw
}

fn dummy_utxo(wallet: &kaspa_portal::wallet::account::derivation::WalletData) -> UtxoEntry {
    UtxoEntry {
        tx_id: "11".repeat(32),
        index: 0,
        amount: 500_000_000,
        script_public_key: address_to_script_pubkey(&wallet.receive_addresses[0]).expect("source script"),
        block_daa_score: 1,
        covenant_id: None,
    }
}

fn deterministic_account_xprv(seed_byte: u8) -> ImportedAccountXprv {
    let seed = [seed_byte; 64];
    let mut encoded = [0u8; XPRV_MAX_LEN];
    let len = derive_and_serialize_xprv(&seed, &mut encoded).expect("derive deterministic xprv");
    import_xprv_with_metadata(&encoded[..len]).expect("import deterministic account xprv")
}

fn sign_pskb_for_account(
    wire: &str,
    imported: &ImportedAccountXprv,
    entropy_byte: u8,
    network_name: &str,
) -> String {
    let relay_hex = relay_pskb_as_kspt_hex_for_network(wire, network_name)
        .expect("relay browser fixture PSKB as compact KSPT");
    let relay = hex::decode(relay_hex).expect("decode browser fixture relay");
    let mut transaction = Transaction::new();
    parse_compact_kspt(&relay, &mut transaction).expect("parse browser fixture relay");
    let signed = sign_transaction_account_multi_addr_with_entropy(
        &mut transaction,
        &imported.key,
        SigHashType::All,
        &[entropy_byte; 32],
    )
    .expect("sign browser fixture wallet inputs");
    assert!(signed > 0, "browser fixture had no signable wallet inputs");
    assert!(
        is_fully_signed(&transaction),
        "browser fixture transaction is not fully signed"
    );
    let signed_wire =
        serialize_compact_kspt_vec(&transaction).expect("serialize browser fixture KSPT");
    merge_signed_kspt_into_pskb(&hex::encode(signed_wire), wire)
        .expect("merge browser fixture signatures")
}

fn raw_scanner_fixture(transaction_id: &[u8; 32], preimage: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(preimage.len() + 1);
    script.push(u8::try_from(preimage.len()).expect("small preimage"));
    script.extend_from_slice(preimage);
    let script_length = script.len().max(10);
    let mut raw = Vec::new();
    raw.extend_from_slice(&37u32.to_le_bytes());
    raw.push(1);
    raw.extend_from_slice(transaction_id);
    raw.extend_from_slice(&7u32.to_le_bytes());
    raw.extend_from_slice(&(script_length as u32).to_le_bytes());
    raw.extend_from_slice(&script);
    raw.resize(raw.len() + script_length.saturating_sub(script.len()), 0);
    raw
}

fn configured_network(env_name: &str, default: &str) -> (String, NetworkId) {
    let name = env::var(env_name).unwrap_or_else(|_| default.to_owned());
    let network = NetworkId::parse(&name).expect("valid configured E2E network");
    (name, network)
}

fn main() {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: browser-parity-fixture <output.json>");

    let (standard_network_name, standard_network) =
        configured_network("KASPA_PORTAL_E2E_STANDARD_NETWORK", "testnet-10");
    let (_, covenant_network) =
        configured_network("KASPA_PORTAL_E2E_COVENANT_NETWORK", "testnet-12");
    let portal = KaspaPortal::builder()
        .network(standard_network)
        .build()
        .expect("offline standard-network portal");
    let covenant_portal = KaspaPortal::builder()
        .network(covenant_network)
        .build()
        .expect("offline covenant-network portal");

    let wallet_api = portal.wallet();
    let kpub = deterministic_kpub(7);
    let raw_kpub = deterministic_raw_kpub(7);
    let wallet = wallet_api.import_kpub(&kpub).expect("import kpub");
    let imported = deterministic_account_xprv(7);
    let raw_wallet = wallet_api.import_kpub_raw(&raw_kpub).expect("import raw kpub");
    let extended = wallet_api.extend_addresses(&wallet, 3, 2).expect("extend wallet");
    let mnemonic12 = wallet_api.mnemonic_12_from_entropy(&[0x11; 16]);
    let mnemonic24 = wallet_api.mnemonic_24_from_entropy(&[0x22; 32]);

    let tx = portal.transaction();
    let destination = wallet.receive_addresses[1].clone();
    let source_script = address_to_script_pubkey(&wallet.receive_addresses[0]).expect("source script");
    let destination_script = address_to_script_pubkey(&destination).expect("destination script");
    let utxo = dummy_utxo(&wallet);
    let planned = tx
        .plan_from_utxos(&wallet, &destination, 100_000_000, 300_000, vec![utxo.clone()])
        .expect("plan transaction");
    let covenant_wallet = covenant_portal
        .wallet()
        .import_kpub(&kpub)
        .expect("import covenant-network kpub");
    let covenant_destination = covenant_wallet.receive_addresses[1].clone();
    let covenant_source_script =
        address_to_script_pubkey(&covenant_wallet.receive_addresses[0]).expect("covenant source script");
    let covenant_destination_script =
        address_to_script_pubkey(&covenant_destination).expect("covenant destination script");
    let covenant_utxo = dummy_utxo(&covenant_wallet);
    let covenant_planned = covenant_portal
        .transaction()
        .plan_from_utxos(
            &covenant_wallet,
            &covenant_destination,
            100_000_000,
            300_000,
            vec![covenant_utxo.clone()],
        )
        .expect("plan covenant-network transaction");
    let payload = b"portal-e2e-payload";
    let with_payload = tx.set_payload(&planned, payload).expect("set payload");
    let lane = tx
        .set_tx_lane(&planned, &"00".repeat(20), 7, 1, payload)
        .expect("set lane");
    let review = tx
        .review(&planned, standard_network.address_prefix())
        .expect("review transaction");
    let signed_payload_wire = sign_pskb_for_account(&with_payload, &imported, 0x74, &standard_network_name);
    let encode_document_input = json!({
        "global": {"txVersion": 0, "fallbackLockTime": "0"},
        "inputs": [],
        "outputs": []
    });
    let encoded_document = tx
        .pskb()
        .encode_document(encode_document_input.clone())
        .expect("encode PSKB document");
    let analysis = tx
        .analyze_with_fee_rate(&signed_payload_wire, 1)
        .expect("analyze signed transaction");
    let finalized = tx
        .finalize(&signed_payload_wire)
        .expect("finalize signed transaction");
    let relay = hex::decode(RELAY_KSPT_HEX).expect("relay KSPT");
    let signed = tx
        .sign_compact_kspt(&relay, &[1u8; 32], SigHashType::All)
        .expect("sign KSPT");
    let signed_entropy = tx
        .sign_compact_kspt_with_entropy(&relay, &[1u8; 32], SigHashType::All, &[2u8; 32])
        .expect("sign KSPT with entropy");
    let mut signed_bytes = vec![0u8; 9 + signed.signatures.len() * 69];
    let signed_len = signed.serialize(&mut signed_bytes).expect("serialize KSSN");
    signed_bytes.truncate(signed_len);
    let mut signed_entropy_bytes = vec![0u8; 9 + signed_entropy.signatures.len() * 69];
    let signed_entropy_len = signed_entropy
        .serialize(&mut signed_entropy_bytes)
        .expect("serialize entropy KSSN");
    signed_entropy_bytes.truncate(signed_entropy_len);

    let contract = covenant_portal.contract();
    let owner = [0x11; 32];
    let second = [0x22; 32];
    let third = [0x33; 32];
    let fourth = [0x44; 32];
    let dms = contract.covenant().dms(&owner, &second, 144);
    let private_swap = contract
        .covenant()
        .private_swap(&owner, &second, &[0x00, 0x00, 0x51], 5_000, &[0x55; 16])
        .expect("private swap");
    let piggy = contract.covenant().piggy_bank(&owner, 25_000_000, 8_000, &[0x66; 8]);
    let savings = contract.covenant().timelocked_savings(&owner, &second, 12_345);
    let payjoin = contract.covenant().payjoin(&owner, &second, 9_999, 2, 2);
    let commit = contract.commit_reveal().build(&owner, &[0x77; 32], 7_777);
    let organizer_spk = {
        let mut value = vec![0x00, 0x00, 0x20];
        value.extend_from_slice(&third);
        value.push(0xac);
        value
    };
    let vk_hash = [0x72; 32];
    let campaign_id = contract
        .crowdfund()
        .campaign_id(100_000_000, 654_321, &vk_hash, &organizer_spk);
    let crowdfund_script = contract
        .crowdfund()
        .redeem_script(CrowdfundScript {
            contributor_pubkey: &owner,
            goal_sompi: 100_000_000,
            locktime_daa: 654_321,
            verifying_key_hash: &vk_hash,
            organizer_output_spk: &organizer_spk,
            salt: &[0x74; 8],
        })
        .expect("crowdfund script");
    let leaves = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    let merkle_root = contract.merkle().root(&leaves);
    let merkle_proof = contract.merkle().proof(&leaves, 1);
    let heartbeat = contract.oracle().heartbeat_script();
    let heartbeat_sig = contract.oracle().heartbeat_sig_script(&heartbeat);
    let consumer_sig = contract.oracle().consumer_sig_script(&heartbeat);
    let sequence = contract.sequence_commit().stealth_proof(&owner, 0x5a);
    let shipping = contract
        .shipping_escrow()
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
        .expect("shipping escrow");
    let tagged = contract.vault().tagged(&owner);
    let split = contract.vault().split(&owner);
    let covenant_id = contract.vault().covenant_id(
        &[0x88; 32],
        3,
        &[(0, 123_000_000, 0, tagged.as_slice()), (1, 45_000_000, 0, split.as_slice())],
    );

    let stealth = portal.privacy().stealth();
    let privacy_kpub = deterministic_kpub(0x31);
    let metadata = stealth.derive_metadata(&privacy_kpub).expect("derive metadata");
    let metadata_encoded = stealth.encode_metadata(&metadata);
    let public_metadata = stealth
        .decode_metadata(&metadata_encoded)
        .expect("decode public stealth metadata");
    let payment = stealth
        .generate_payment(&public_metadata, &[0x53; 32])
        .expect("stealth payment");
    let transaction_id = [0x61; 32];
    let raw_scanner = raw_scanner_fixture(&transaction_id, b"portal-e2e-preimage");

    let indexer = IndexerApi::with_clock(IndexerConfig::default(), || Ok(100))
        .expect("construct indexer");
    indexer.start().expect("start indexer");
    indexer.watch_address("kaspatest:e2e-address").expect("matcher");
    indexer
        .watch_payload_exact(b"portal-e2e-payload".to_vec())
        .expect("payload matcher");
    let indexed_transaction = IndexedTransaction {
        txid: "tx-a".into(),
        block_hash: Some("block-a".into()),
        daa_score: Some(10),
        observed_at_ms: 100,
        addresses: vec!["kaspatest:e2e-address".into()],
        payload: b"portal-e2e-payload".to_vec(),
        raw: json!({"transactionId":"tx-a","payload":hex::encode(b"portal-e2e-payload")}),
    };
    indexer
        .ingest_transaction(indexed_transaction.clone())
        .expect("ingest transaction");
    indexer
        .ingest_block(IndexedBlock {
            hash: "block-a".into(),
            daa_score: Some(10),
            observed_at_ms: 100,
            txids: vec!["tx-a".into()],
            raw: json!({"hash":"block-a","daaScore":"10"}),
        })
        .expect("ingest block");
    let indexer_metrics = indexer.metrics().expect("indexer metrics");
    let indexer_state = indexer.persisted_state().expect("indexer state");

    let randomness = portal.randomness();
    let evidence = KaspaEntropyEvidence::finalized([0x41; 32], Some(123_456));
    randomness
        .beacon()
        .observe_kaspa_block(evidence.clone())
        .expect("observe evidence");
    let beacon_request = BeaconRequest {
        network: standard_network,
        context: b"kaspa-portal-e2e".to_vec(),
        kaspa: vec![evidence],
        curby: None,
        extractor: ExtractorConfig::default(),
    };
    let beacon_request_json = serde_json::to_value(&beacon_request).expect("beacon request JSON");
    let beacon = randomness
        .beacon()
        .generate(beacon_request)
        .expect("generate beacon");
    let beacon_verification = randomness.beacon().verify(&beacon).expect("verify beacon");
    let vrf_secret = VrfSecretKey::from_bytes([0x21; 32]);
    let vrf_public = vrf_secret.public_key();
    let vrf_result = randomness
        .vrf()
        .prove(&vrf_secret, b"kaspa-portal-e2e-vrf")
        .expect("VRF prove");

    let fixture = json!({
        "schema": 1,
        "wallet": {
            "kpub": kpub,
            "rawKpub": hex::encode(raw_kpub),
            "wallet": wallet,
            "rawWallet": raw_wallet,
            "extended": extended,
            "mnemonic12": {"indices": mnemonic12.indices},
            "mnemonic24": {"indices": mnemonic24.indices},
            "prefix": wallet_api.prefix(),
            "multisigKpub1": deterministic_multisig_kpub(0x61),
            "multisigKpub2": deterministic_multisig_kpub(0x62)
        },
        "transaction": {
            "destination": destination,
            "utxo": utxo,
            "sourceScriptHex": hex::encode(source_script),
            "destinationScriptHex": hex::encode(destination_script),
            "planned": planned,
            "payloadHex": hex::encode(payload),
            "withPayload": with_payload,
            "lane": lane,
            "analysis": analysis,
            "analysisWire": signed_payload_wire,
            "review": review,
            "encodeDocumentInput": encode_document_input,
            "encodedDocument": encoded_document,
            "finalized": finalized,
            "relayKsptHex": RELAY_KSPT_HEX,
            "signedKssnHex": hex::encode(signed_bytes),
            "signedEntropyKssnHex": hex::encode(signed_entropy_bytes),
            "covenant": {
                "planned": covenant_planned,
                "utxo": covenant_utxo,
                "sourceScriptHex": hex::encode(covenant_source_script),
                "destinationScriptHex": hex::encode(covenant_destination_script)
            }
        },
        "contract": {
            "owner": hex::encode(owner),
            "second": hex::encode(second),
            "third": hex::encode(third),
            "fourth": hex::encode(fourth),
            "dms": hex::encode(&dms),
            "dmsAddress": contract
                .script()
                .p2sh_address(&dms, covenant_network.address_prefix())
                .expect("p2sh"),
            "privateSwap": hex::encode(private_swap),
            "piggyBank": hex::encode(piggy),
            "timelockedSavings": hex::encode(savings),
            "payjoin": hex::encode(payjoin),
            "commitReveal": hex::encode(commit),
            "organizerSpk": hex::encode(&organizer_spk),
            "verifyingKeyHash": hex::encode(vk_hash),
            "campaignId": hex::encode(campaign_id),
            "crowdfundScript": hex::encode(crowdfund_script),
            "merkleLeaves": leaves.iter().map(hex::encode).collect::<Vec<_>>(),
            "merkleRoot": hex::encode(merkle_root),
            "merkleProof": merkle_proof.iter().map(|(hash, direction)| json!({"hash":hex::encode(hash),"direction":direction})).collect::<Vec<_>>(),
            "heartbeat": hex::encode(&heartbeat),
            "heartbeatSig": hex::encode(heartbeat_sig),
            "consumerSig": hex::encode(consumer_sig),
            "sequenceProof": {"subnetworkId": sequence.subnetwork_id_hex, "gas":sequence.gas.to_string(), "transactionVersion":sequence.transaction_version, "payload":hex::encode(sequence.payload)},
            "shipping": hex::encode(shipping),
            "taggedVault": hex::encode(&tagged),
            "splitVault": hex::encode(&split),
            "covenantId": hex::encode(covenant_id)
        },
        "privacy": {
            "kpub": privacy_kpub,
            "metadata": metadata_encoded,
            "payment": {"oneTimePubkey":hex::encode(payment.one_time_pubkey),"ephemeralPubkey":hex::encode(payment.ephemeral_pubkey),"stealthIndex":payment.stealth_index,"viewTag":payment.view_tag},
            "announcement": stealth.announcement_address(standard_network.address_prefix()),
            "scannerRaw": hex::encode(raw_scanner),
            "scannerTxid": hex::encode(transaction_id),
            "scannerExpected": hex::encode(b"portal-e2e-preimage")
        },
        "indexer": {
            "transaction": indexed_transaction,
            "metrics": indexer_metrics,
            "persistedState": indexer_state
        },
        "randomness": {
            "beaconRequest": beacon_request_json,
            "beacon": beacon,
            "beaconVerification": beacon_verification,
            "vrfSecret": hex::encode([0x21;32]),
            "vrfPublic": hex::encode(vrf_public.0),
            "vrfInput": hex::encode(b"kaspa-portal-e2e-vrf"),
            "vrfResult": vrf_result
        }
    });

    fs::write(&output, serde_json::to_vec_pretty(&fixture).expect("fixture JSON"))
        .expect("write fixture");
}

