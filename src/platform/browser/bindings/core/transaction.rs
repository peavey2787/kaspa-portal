use wasm_bindgen::prelude::*;

use crate::{
    chain::utxo::UtxoEntry,
    transaction::{interchange::kspt::SignedResponse, model::SigHashType, TransactionApi},
    wallet::account::derivation::WalletData,
};

use super::{decimal, decode, encode, js_error};

mod pskb;
mod requests;
pub use pskb::WasmPskb;
use requests::{CovenantPlanJson, MultisigConsolidationJson};

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

    /// Plan a multisig consolidation from one camelCase request object:
    /// `descriptorText`, `sources`, `destinationAddress`, `amountSompi`,
    /// `feeSompi`, `cosigner` and `changeIndexHint`.
    #[wasm_bindgen(js_name = planMultisigConsolidation)]
    pub async fn plan_multisig_consolidation(&self, request_json: &str) -> Result<String, JsValue> {
        let request: MultisigConsolidationJson = decode(request_json)?;
        let sources = request.encoded_sources()?;
        self.inner
            .plan_multisig_consolidation(request.request(&sources)?)
            .await
            .map_err(js_error)
    }

    /// Plan a covenant send from one camelCase request object: `wallet`,
    /// `covenantAddress`, `sendAmountSompi`, `feeSompi`, `changeAddress`,
    /// `utxoIndicesCsv` and `encoding` (`{kind: "payload", payloadHex,
    /// tagGenesis}` or `{kind: "boundGenesis"}`).
    #[wasm_bindgen(js_name = planCovenant)]
    pub async fn plan_covenant(&self, request_json: &str) -> Result<String, JsValue> {
        let request: CovenantPlanJson = decode(request_json)?;
        self.inner
            .plan_covenant(request.request()?)
            .await
            .map_err(js_error)
    }

    /// [`Self::plan_covenant`] that also reports the bound covenant ID.
    #[wasm_bindgen(js_name = planCovenantWithBinding)]
    pub async fn plan_covenant_with_binding(&self, request_json: &str) -> Result<String, JsValue> {
        let request: CovenantPlanJson = decode(request_json)?;
        let (wire, binding) = self
            .inner
            .plan_covenant_with_binding(request.request()?)
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
