//! Shared fixtures for pipeline and consensus tests.

/// The KasKold signer capacity these vectors were written against.
pub(crate) const SIGNER_TEST_LIMITS: crate::transaction::interchange::kspt::wire::Limits =
    crate::transaction::interchange::kspt::wire::Limits::new(32, 8, 768);

pub(crate) use super::relay_fields::{
    find_pubkey_position, parse_ms45, parse_multisig_redeem, InputFields,
};
pub(crate) use super::wire::{
    decode, document, encode, parse_derivation, Format, MAX_PSKT_WIRE_HEX_CHARS,
};

pub(crate) fn sighash_all_for_pskt(
    pskt_hex: &str,
    network: crate::primitives::address::KaspaNetwork,
    input_index: usize,
) -> Result<[u8; 32], String> {
    super::compact::test_sighash_all_for_pskt(pskt_hex, network, input_index)
}

pub(crate) fn compact_covenant_execution_for_test(
    data: &[u8],
    input_index: usize,
) -> Result<Option<(u16, u16)>, String> {
    let transaction = super::compact::parse(
        data,
        crate::transaction::interchange::kspt::wire::Limits::grammar(),
    )?;
    transaction
        .inputs
        .get(input_index)
        .map(|input| input.covenant_execution)
        .ok_or_else(|| "KSPT input index out of range".to_string())
}

/// The x-only public key of the deterministic test signer `marker`.
pub(crate) fn xonly(marker: u8) -> [u8; 32] {
    signing_key(marker).verifying_key().to_bytes().into()
}

fn signing_key(marker: u8) -> k256::schnorr::SigningKey {
    k256::schnorr::SigningKey::from_bytes(&[marker; 32]).expect("test signing key")
}

/// `m`-of-`n` multisig over the deterministic test signers `keys`.
pub(crate) fn multisig(keys: &[u8], threshold: u8) -> Vec<u8> {
    let mut script = vec![0x50 + threshold];
    for key in keys {
        script.push(0x20);
        script.extend_from_slice(&xonly(*key));
    }
    script.push(0x50 + u8::try_from(keys.len()).expect("test multisig key count"));
    script.push(0xae);
    script
}

/// Wrap one PSKT document in a PSKB envelope.
pub(crate) fn pskb(document: &serde_json::Value) -> String {
    encode(Format::Pskb, &serde_json::json!([document])).expect("encode test PSKB")
}

/// Add a SIGHASH_ALL partial signature from each test signer to input 0.
pub(crate) fn sign_first_input(
    mut document: serde_json::Value,
    signers: &[u8],
) -> serde_json::Value {
    let digest = sighash_all_for_pskt(
        &pskb(&document),
        crate::primitives::address::KaspaNetwork::Mainnet,
        0,
    )
    .expect("test sighash");
    let partials = document["inputs"][0]["partialSigs"]
        .as_object_mut()
        .expect("partialSigs object");
    for marker in signers {
        let signing = signing_key(*marker);
        let signature = signing
            .sign_raw(&digest, &[0u8; 32])
            .expect("test signature");
        partials.insert(
            format!("02{}", hex::encode(signing.verifying_key().to_bytes())),
            serde_json::json!({"schnorr": hex::encode(signature.to_bytes())}),
        );
    }
    document
}

/// One-input, one-output PSKT spending the test signer's P2PK, or the P2SH
/// of `redeem` when one is given.
pub(crate) fn unsigned_document(redeem: Option<&[u8]>, signer: u8) -> serde_json::Value {
    let input_script = if let Some(redeem) = redeem {
        let hash = blake2b_simd::Params::new().hash_length(32).hash(redeem);
        format!("0000aa20{}87", hex::encode(hash.as_bytes()))
    } else {
        format!("000020{}ac", hex::encode(xonly(signer)))
    };
    serde_json::json!({
        "global": {
            "version": 0,
            "txVersion": 0,
            "inputCount": 1,
            "outputCount": 1,
            "fallbackLockTime": "0",
            "subnetworkId": "00".repeat(20),
            "gas": "0",
            "txPayload": ""
        },
        "inputs": [{
            "previousOutpoint": {"transactionId": "22".repeat(32), "index": 7},
            "utxoEntry": {"amount": "100000", "scriptPublicKey": input_script},
            "sequence": "0",
            "sigOpCount": 1,
            "sighashType": 1,
            "redeemScript": redeem.map(hex::encode),
            "partialSigs": {},
            "proprietaries": {}
        }],
        "outputs": [{
            "amount": "90000",
            "scriptPublicKey": "000051",
            "covenantBinding": null
        }]
    })
}
