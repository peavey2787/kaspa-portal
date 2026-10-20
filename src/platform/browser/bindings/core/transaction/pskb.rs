use wasm_bindgen::prelude::*;

use crate::{
    chain::utxo::UtxoEntry,
    transaction::builder::{PskbGlobalPlan, PskbPlan, SweepInputPolicy},
};

use super::bytes_hex;
use super::requests::{GlobalThreadTopupJson, GlobalThreadWithdrawalJson};
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

    /// Plan a global-thread withdrawal from one camelCase request object:
    /// `threadUtxos`, `covenantScriptPublicKeyHex`,
    /// `destinationScriptPublicKeyHex`, `redeemScriptHex`, `covenantIdHex`,
    /// `withdrawalSompi`, `feeSompi`, `csvSequence` and `policy`.
    #[wasm_bindgen(js_name = planGlobalThreadWithdrawal)]
    pub fn plan_global_thread_withdrawal(&self, request_json: &str) -> Result<String, JsValue> {
        let request: GlobalThreadWithdrawalJson = decode(request_json)?;
        let plan = request
            .plan(|request| self.inner.plan_global_thread_withdrawal(request))?
            .map_err(js_error)?;
        encode(&plan)
    }

    /// Plan a global-thread top-up from one camelCase request object:
    /// `threadUtxo`, `walletUtxos`, `covenantScriptPublicKeyHex`,
    /// `redeemScriptHex`, `covenantIdHex`, `feeSompi` and `policy`.
    #[wasm_bindgen(js_name = planGlobalThreadTopup)]
    pub fn plan_global_thread_topup(&self, request_json: &str) -> Result<String, JsValue> {
        let request: GlobalThreadTopupJson = decode(request_json)?;
        let plan = request
            .plan(|request| self.inner.plan_global_thread_topup(request))?
            .map_err(js_error)?;
        encode(&plan)
    }
}
