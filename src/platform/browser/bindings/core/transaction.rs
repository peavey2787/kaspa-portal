use wasm_bindgen::prelude::*;

use crate::{
    chain::utxo::UtxoEntry,
    transaction::{
        builder::{CovenantBuildRequest, CovenantEncoding, MultisigConsolidationRequest},
        interchange::kspt::SignedResponse,
        model::SigHashType,
        TransactionApi,
    },
    wallet::account::derivation::WalletData,
};

use super::{decimal, decode, encode, js_error};

mod pskb;
pub use pskb::WasmPskb;

#[wasm_bindgen(js_name = KaspaTransaction)]
pub struct WasmTransaction {
    inner: TransactionApi,
}

impl WasmTransaction {
    pub(crate) fn from_api(inner: TransactionApi) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen(js_class = KaspaTransaction)]
impl WasmTransaction {
    pub fn pskb(&self) -> WasmPskb {
        WasmPskb::from_api(self.inner.pskb())
    }

    #[wasm_bindgen(js_name = planSend)]
    pub async fn plan_send(
        &self,
        wallet_json: &str,
        destination: &str,
        amount_sompi: &str,
        fee_sompi: &str,
    ) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        self.inner
            .plan_send(
                &wallet,
                destination,
                decimal(amount_sompi, "amount")?,
                decimal(fee_sompi, "fee")?,
            )
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = planSendWithPayload)]
    pub async fn plan_send_with_payload(
        &self,
        wallet_json: &str,
        destination: &str,
        amount_sompi: &str,
        fee_sompi: &str,
        payload: &[u8],
    ) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        self.inner
            .plan_send_with_payload(
                &wallet,
                destination,
                decimal(amount_sompi, "amount")?,
                decimal(fee_sompi, "fee")?,
                payload,
            )
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = planSelectedSend)]
    pub async fn plan_selected_send(
        &self,
        wallet_json: &str,
        destination: &str,
        amount_sompi: &str,
        fee_sompi: &str,
        indices_json: &str,
    ) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        let indices: Vec<usize> = decode(indices_json)?;
        self.inner
            .plan_selected_send(
                &wallet,
                destination,
                decimal(amount_sompi, "amount")?,
                decimal(fee_sompi, "fee")?,
                &indices,
            )
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = planConsolidation)]
    pub async fn plan_consolidation(
        &self,
        wallet_json: &str,
        fee_sompi: &str,
    ) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        self.inner
            .plan_consolidation(&wallet, decimal(fee_sompi, "fee")?)
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = scanMultisigBranch)]
    pub async fn scan_multisig_branch(
        &self,
        descriptor_text: &str,
        cosigner: u32,
        depth: u32,
        prefix: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .scan_multisig_branch(descriptor_text, cosigner, depth, prefix)
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = planMultisigConsolidation)]
    pub async fn plan_multisig_consolidation(
        &self,
        descriptor_text: &str,
        sources_json: &str,
        destination_address: &str,
        amount_sompi: &str,
        fee_sompi: &str,
        cosigner: u32,
        change_index_hint: u32,
    ) -> Result<String, JsValue> {
        self.inner
            .plan_multisig_consolidation(MultisigConsolidationRequest {
                descriptor_text,
                sources_json,
                destination_address,
                amount: decimal(amount_sompi, "amount")?,
                fee: decimal(fee_sompi, "fee")?,
                cosigner,
                change_index_hint,
            })
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = planCovenant)]
    pub async fn plan_covenant(
        &self,
        wallet_json: &str,
        covenant_address: &str,
        send_amount_sompi: &str,
        fee_sompi: &str,
        change_address: &str,
        utxo_indices_csv: &str,
        encoding_kind: &str,
        payload_hex: &str,
        tag_genesis: bool,
    ) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        let encoding = covenant_encoding(encoding_kind, payload_hex, tag_genesis)?;
        self.inner
            .plan_covenant(CovenantBuildRequest {
                wallet: &wallet,
                covenant_address,
                send_amount: decimal(send_amount_sompi, "send amount")?,
                fee: decimal(fee_sompi, "fee")?,
                change_address,
                utxo_indices_csv,
                encoding,
            })
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = planCovenantWithBinding)]
    pub async fn plan_covenant_with_binding(
        &self,
        wallet_json: &str,
        covenant_address: &str,
        send_amount_sompi: &str,
        fee_sompi: &str,
        change_address: &str,
        utxo_indices_csv: &str,
        encoding_kind: &str,
        payload_hex: &str,
        tag_genesis: bool,
    ) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        let encoding = covenant_encoding(encoding_kind, payload_hex, tag_genesis)?;
        let (wire, binding) = self
            .inner
            .plan_covenant_with_binding(CovenantBuildRequest {
                wallet: &wallet,
                covenant_address,
                send_amount: decimal(send_amount_sompi, "send amount")?,
                fee: decimal(fee_sompi, "fee")?,
                change_address,
                utxo_indices_csv,
                encoding,
            })
            .await
            .map_err(js_error)?;
        Ok(serde_json::json!({
            "wire": wire,
            "covenantId": binding.map(hex::encode),
        })
        .to_string())
    }

    #[wasm_bindgen(js_name = planFromUtxos)]
    pub fn plan_from_utxos(
        &self,
        wallet_json: &str,
        destination: &str,
        amount_sompi: &str,
        fee_sompi: &str,
        utxos_json: &str,
    ) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        let utxos: Vec<UtxoEntry> = decode(utxos_json)?;
        self.inner
            .plan_from_utxos(
                &wallet,
                destination,
                decimal(amount_sompi, "amount")?,
                decimal(fee_sompi, "fee")?,
                utxos,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = setPayload)]
    pub fn set_payload(&self, wire_hex: &str, payload: &[u8]) -> Result<String, JsValue> {
        self.inner.set_payload(wire_hex, payload).map_err(js_error)
    }

    #[wasm_bindgen(js_name = setTxLane)]
    pub fn set_tx_lane(
        &self,
        wire_hex: &str,
        subnetwork_id_hex: &str,
        gas: &str,
        tx_version: u16,
        payload: &[u8],
    ) -> Result<String, JsValue> {
        self.inner
            .set_tx_lane(
                wire_hex,
                subnetwork_id_hex,
                decimal(gas, "gas")?,
                tx_version,
                payload,
            )
            .map_err(js_error)
    }

    pub async fn analyze(&self, wire_hex: &str) -> Result<String, JsValue> {
        encode(&self.inner.analyze(wire_hex).await.map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = analyzeWithFeeRate)]
    pub fn analyze_with_fee_rate(
        &self,
        wire_hex: &str,
        fee_rate_sompi_per_gram: &str,
    ) -> Result<String, JsValue> {
        encode(
            &self
                .inner
                .analyze_with_fee_rate(wire_hex, decimal(fee_rate_sompi_per_gram, "fee rate")?)
                .map_err(js_error)?,
        )
    }

    pub fn review(&self, wire_hex: &str, network_prefix: &str) -> Result<String, JsValue> {
        encode(
            &self
                .inner
                .review(wire_hex, network_prefix)
                .map_err(js_error)?,
        )
    }

    pub fn finalize(&self, wire_hex: &str) -> Result<String, JsValue> {
        encode(&self.inner.finalize(wire_hex).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = signCompactKspt)]
    pub fn sign_compact_kspt(
        &self,
        wire: &[u8],
        private_key_hex: &str,
        sighash_byte: u8,
    ) -> Result<String, JsValue> {
        let private_key = fixed32(private_key_hex, "private key")?;
        let sighash = sighash(sighash_byte)?;
        serialize_response(
            &self
                .inner
                .sign_compact_kspt(wire, &private_key, sighash)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = signCompactKsptWithEntropy)]
    pub fn sign_compact_kspt_with_entropy(
        &self,
        wire: &[u8],
        private_key_hex: &str,
        sighash_byte: u8,
        signing_entropy_hex: &str,
    ) -> Result<String, JsValue> {
        let private_key = fixed32(private_key_hex, "private key")?;
        let entropy = fixed32(signing_entropy_hex, "signing entropy")?;
        let sighash = sighash(sighash_byte)?;
        serialize_response(
            &self
                .inner
                .sign_compact_kspt_with_entropy(wire, &private_key, sighash, &entropy)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = applySequenceCommitProof)]
    pub fn apply_sequence_commit_proof(
        &self,
        wire_hex: &str,
        subnetwork_id_hex: &str,
        gas: &str,
        transaction_version: u16,
        payload: &[u8],
    ) -> Result<String, JsValue> {
        self.inner
            .set_tx_lane(
                wire_hex,
                subnetwork_id_hex,
                decimal(gas, "gas")?,
                transaction_version,
                payload,
            )
            .map_err(js_error)
    }

    pub async fn broadcast(&self, wire_hex: &str) -> Result<String, JsValue> {
        let transaction = self.inner.finalize(wire_hex).map_err(js_error)?;
        self.inner.broadcast(&transaction).await.map_err(js_error)
    }

    #[wasm_bindgen(js_name = broadcastWire)]
    pub async fn broadcast_wire(&self, wire_hex: &str) -> Result<String, JsValue> {
        self.broadcast(wire_hex).await
    }
}

fn covenant_encoding<'a>(
    kind: &str,
    payload_hex: &'a str,
    tag_genesis: bool,
) -> Result<CovenantEncoding<'a>, JsValue> {
    match kind {
        "payload" => Ok(CovenantEncoding::Payload {
            payload_hex,
            tag_genesis,
        }),
        "boundGenesis" | "bound_genesis" => Ok(CovenantEncoding::BoundGenesis),
        _ => Err(JsValue::from_str(
            "encoding kind must be 'payload' or 'boundGenesis'",
        )),
    }
}

fn sighash(value: u8) -> Result<SigHashType, JsValue> {
    SigHashType::from_byte(value).ok_or_else(|| JsValue::from_str("invalid sighash type"))
}

pub(super) fn fixed32(value: &str, name: &str) -> Result<[u8; 32], JsValue> {
    let bytes = bytes_hex(value, name)?;
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{name} must be 32 bytes")))
}

pub(super) fn bytes_hex(value: &str, name: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(value).map_err(|error| JsValue::from_str(&format!("invalid {name}: {error}")))
}

fn serialize_response(response: &SignedResponse) -> Result<String, JsValue> {
    let capacity = 9usize.saturating_add(response.signatures.len().saturating_mul(69));
    let mut output = vec![0u8; capacity];
    let length = response
        .serialize(&mut output)
        .map_err(|error| JsValue::from_str(&format!("KSSN serialize failed: {error:?}")))?;
    output.truncate(length);
    Ok(hex::encode(output))
}
