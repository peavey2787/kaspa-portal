use std::hint::black_box;

use kaspa_portal::{
    contract::{crowdfund::CrowdfundScript, shipping_escrow::ShippingEscrowScriptRequest},
    primitives::address::address_to_script_pubkey,
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
        derive_and_serialize_kpub, derive_and_serialize_xprv, import_xprv_with_metadata,
        KPUB_MAX_LEN, XPRV_MAX_LEN,
    },
    KaspaPortal,
};

use kaspa_portal::chain::utxo::UtxoEntry;

fn sign_pskb_for_seed(wire: &str, seed: &[u8; 64]) -> Result<String, String> {
    let mut encoded = [0u8; XPRV_MAX_LEN];
    let len = derive_and_serialize_xprv(seed, &mut encoded).map_err(|error| error.to_string())?;
    let imported =
        import_xprv_with_metadata(&encoded[..len]).map_err(|error| error.to_string())?;
    let relay_hex = relay_pskb_as_kspt_hex_for_network(wire, &super::standard_network_name())?;
    let relay = hex::decode(relay_hex).map_err(|error| error.to_string())?;
    let mut transaction = Transaction::new();
    parse_compact_kspt(&relay, &mut transaction)
        .map_err(|error| format!("parse resource-probe KSPT: {error:?}"))?;
    let signed = sign_transaction_account_multi_addr_with_entropy(
        &mut transaction,
        &imported.key,
        SigHashType::All,
        &[0x75; 32],
    )
    .map_err(|error| format!("sign resource-probe KSPT: {error:?}"))?;
    if signed == 0 || !is_fully_signed(&transaction) {
        return Err("resource-probe transaction was not fully signed".to_string());
    }
    let signed_wire = serialize_compact_kspt_vec(&transaction)
        .map_err(|error| format!("serialize resource-probe KSPT: {error:?}"))?;
    merge_signed_kspt_into_pskb(&hex::encode(signed_wire), wire)
}

pub fn run(iteration: usize) -> Result<(), String> {
    let portal = KaspaPortal::builder()
        .network(super::standard_network())
        .build()
        .map_err(|error| error.to_string())?;
    let wallet_api = portal.wallet();
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let seed = [u8::try_from(iteration & 0xff).unwrap_or(0x41); 64];
    let len = derive_and_serialize_kpub(&seed, &mut encoded).map_err(|error| error.to_string())?;
    let kpub = std::str::from_utf8(&encoded[..len]).map_err(|error| error.to_string())?;
    let wallet = wallet_api.import_kpub(kpub).map_err(|error| error.to_string())?;
    let source = wallet.receive_addresses[0].clone();
    let destination = wallet.receive_addresses[1].clone();
    let source_script = address_to_script_pubkey(&source)?;
    let utxo = UtxoEntry {
        tx_id: format!("{:02x}", (iteration & 0xff) as u8).repeat(32),
        index: 0,
        amount: 500_000_000,
        script_public_key: source_script,
        block_daa_score: 1,
        covenant_id: None,
    };
    let planned = portal
        .transaction()
        .plan_from_utxos(&wallet, &destination, 100_000_000, 300_000, vec![utxo])
        .map_err(|error| error.to_string())?;
    let payload = portal
        .transaction()
        .set_payload(&planned, b"resource-probe")
        .map_err(|error| error.to_string())?;
    let analysis_wire = sign_pskb_for_seed(&payload, &seed)?;
    let analysis = portal
        .transaction()
        .analyze_with_fee_rate(&analysis_wire, 1)
        .map_err(|error| error.to_string())?;

    let covenant_portal = KaspaPortal::builder()
        .network(super::covenant_network())
        .build()
        .map_err(|error| error.to_string())?;
    let contract = covenant_portal.contract();
    let owner = [0x11; 32];
    let second = [0x22; 32];
    let third = [0x33; 32];
    let fourth = [0x44; 32];
    let dms = contract.covenant().dms(&owner, &second, 144);
    let _ = contract
        .script()
        .p2sh_address(&dms, super::covenant_network().address_prefix()).map_err(|error| error.to_string())?;
    let _ = contract
        .covenant()
        .private_swap(&owner, &second, &[0, 0, 0x51], 5_000, &[0x55; 16])
        .map_err(|error| error.to_string())?;
    let _ = contract.covenant().piggy_bank(&owner, 25_000_000, 8_000, &[0x66; 8]);
    let _ = contract.covenant().timelocked_savings(&owner, &second, 12_345);
    let _ = contract.covenant().payjoin(&owner, &second, 9_999, 2, 2);
    let _ = contract.commit_reveal().build(&owner, &[0x77; 32], 7_777);
    let organizer_spk = {
        let mut value = vec![0x00, 0x00, 0x20];
        value.extend_from_slice(&third);
        value.push(0xac);
        value
    };
    let _ = contract
        .crowdfund()
        .redeem_script(CrowdfundScript {
            contributor_pubkey: &owner,
            goal_sompi: 100_000_000,
            locktime_daa: 654_321,
            verifying_key_hash: &[0x72; 32],
            organizer_output_spk: &organizer_spk,
            salt: &[0x74; 8],
        })
        .map_err(|error| error.to_string())?;
    let leaves = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    let _ = contract.merkle().root(&leaves);
    let _ = contract.merkle().proof(&leaves, 1);
    let heartbeat = contract.oracle().heartbeat_script();
    let _ = contract.oracle().heartbeat_sig_script(&heartbeat);
    let _ = contract.oracle().consumer_sig_script(&heartbeat);
    let _ = contract.sequence_commit().stealth_proof(&owner, 0x5a);
    let _ = contract.shipping_escrow().build(ShippingEscrowScriptRequest {
        seller_pubkey: &owner,
        deliverer_pubkey: &second,
        buyer_pubkey: &third,
        arbiter_pubkey: &fourth,
        product_sompi: 200_000_000,
        fee_sompi: 1_000_000,
        cltv1_deadline: 50_000,
        cltv2_deadline: 60_000,
        salt: &[0x35; 8],
    }).map_err(|error| error.to_string())?;
    let tagged = contract.vault().tagged(&owner);
    let split = contract.vault().split(&owner);
    let _ = contract.vault().covenant_id(
        &[0x88; 32],
        3,
        &[(0, 123_000_000, 0, tagged.as_slice()), (1, 45_000_000, 0, split.as_slice())],
    );
    black_box((payload, analysis.normalized_mass, tagged, split));
    Ok(())
}
