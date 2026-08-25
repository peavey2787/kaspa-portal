use wasm_bindgen::prelude::*;

use crate::{
    chain::utxo::UtxoEntry,
    transaction::builder::{
        GlobalThreadPolicy, GlobalThreadTopupRequest, GlobalThreadWithdrawalRequest,
        PskbGlobalPlan, PskbPlan, SweepInputPolicy,
    },
};

use super::{bytes_hex, fixed32};
use crate::platform::browser::bindings::core::{decimal, decode, encode, js_error};

#[wasm_bindgen(js_name = KaspaPskb)]
pub struct WasmPskb {
    inner: crate::transaction::builder::PskbApi,
}

impl WasmPskb {
    pub(super) fn from_api(inner: crate::transaction::builder::PskbApi) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen(js_class = KaspaPskb)]
impl WasmPskb {
    pub fn encode(&self, plan_json: &str) -> Result<String, JsValue> {
        let plan: PskbPlan = decode(plan_json)?;
        self.inner.encode(&plan).map_err(js_error)
    }

    #[wasm_bindgen(js_name = encodeDocument)]
    pub fn encode_document(&self, document_json: &str) -> Result<String, JsValue> {
        let document: serde_json::Value = decode(document_json)?;
        self.inner.encode_document(document).map_err(js_error)
    }

    #[wasm_bindgen(js_name = planSweep)]
    pub fn plan_sweep(
        &self,
        utxos_json: &str,
        source_script_public_key_hex: &str,
        destination_script_public_key_hex: &str,
        send_amount_sompi: &str,
        global_json: &str,
        input_policy_json: &str,
    ) -> Result<String, JsValue> {
        let utxos: Vec<UtxoEntry> = decode(utxos_json)?;
        let global: PskbGlobalPlan = decode(global_json)?;
        let input_policy: SweepInputPolicy = decode(input_policy_json)?;
        let source = bytes_hex(source_script_public_key_hex, "source script public key")?;
        let destination = bytes_hex(
            destination_script_public_key_hex,
            "destination script public key",
        )?;
        encode(&self.inner.plan_sweep(
            &utxos,
            &source,
            &destination,
            decimal(send_amount_sompi, "send amount")?,
            global,
            &input_policy,
        ))
    }

    #[wasm_bindgen(js_name = planGlobalThreadWithdrawal)]
    pub fn plan_global_thread_withdrawal(
        &self,
        thread_utxos_json: &str,
        covenant_script_public_key_hex: &str,
        destination_script_public_key_hex: &str,
        redeem_script_hex: &str,
        covenant_id_hex: &str,
        withdrawal_sompi: &str,
        fee_sompi: &str,
        csv_sequence: &str,
        policy_json: &str,
    ) -> Result<String, JsValue> {
        let thread_utxos: Vec<UtxoEntry> = decode(thread_utxos_json)?;
        let covenant_script = bytes_hex(covenant_script_public_key_hex, "covenant script")?;
        let destination_script =
            bytes_hex(destination_script_public_key_hex, "destination script")?;
        let redeem_script = bytes_hex(redeem_script_hex, "redeem script")?;
        let covenant_id = fixed32(covenant_id_hex, "covenant id")?;
        let policy: GlobalThreadPolicy = decode(policy_json)?;
        encode(
            &self
                .inner
                .plan_global_thread_withdrawal(GlobalThreadWithdrawalRequest {
                    thread_utxos: &thread_utxos,
                    covenant_script_public_key: &covenant_script,
                    destination_script_public_key: &destination_script,
                    redeem_script: &redeem_script,
                    covenant_id: &covenant_id,
                    withdrawal: decimal(withdrawal_sompi, "withdrawal")?,
                    fee: decimal(fee_sompi, "fee")?,
                    csv_sequence: decimal(csv_sequence, "CSV sequence")?,
                    policy: &policy,
                })
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = planGlobalThreadTopup)]
    pub fn plan_global_thread_topup(
        &self,
        thread_utxo_json: &str,
        wallet_utxos_json: &str,
        covenant_script_public_key_hex: &str,
        redeem_script_hex: &str,
        covenant_id_hex: &str,
        fee_sompi: &str,
        policy_json: &str,
    ) -> Result<String, JsValue> {
        let thread_utxo: UtxoEntry = decode(thread_utxo_json)?;
        let wallet_utxos: Vec<UtxoEntry> = decode(wallet_utxos_json)?;
        let covenant_script = bytes_hex(covenant_script_public_key_hex, "covenant script")?;
        let redeem_script = bytes_hex(redeem_script_hex, "redeem script")?;
        let covenant_id = fixed32(covenant_id_hex, "covenant id")?;
        let policy: GlobalThreadPolicy = decode(policy_json)?;
        encode(
            &self
                .inner
                .plan_global_thread_topup(GlobalThreadTopupRequest {
                    thread_utxo,
                    wallet_utxos: &wallet_utxos,
                    covenant_script_public_key: &covenant_script,
                    redeem_script: &redeem_script,
                    covenant_id: &covenant_id,
                    fee: decimal(fee_sompi, "fee")?,
                    policy: &policy,
                })
                .map_err(js_error)?,
        )
    }
}
