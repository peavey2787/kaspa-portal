//! Single-object JSON requests for the browser planners whose inputs are too
//! many to pass positionally. Keys are camelCase; nested wallets, UTXOs and
//! policies keep their own serde form, and unknown keys are refused.

use serde::Deserialize;
use wasm_bindgen::JsValue;

use crate::{
    chain::utxo::UtxoEntry,
    transaction::builder::{
        CovenantBuildRequest, CovenantDustPolicy, CovenantEncoding, GlobalThreadPolicy,
        GlobalThreadTopupRequest, GlobalThreadWithdrawalRequest, MultisigConsolidationRequest,
    },
    wallet::account::derivation::WalletData,
};

use super::{bytes_hex, fixed32};
use crate::platform::browser::bindings::core::{decimal, encode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MultisigConsolidationJson {
    descriptor_text: String,
    sources: serde_json::Value,
    destination_address: String,
    amount_sompi: String,
    fee_sompi: String,
    cosigner: u32,
    change_index_hint: u32,
}

impl MultisigConsolidationJson {
    /// Borrow the request; `sources` is the encoded source list it reads.
    pub(super) fn request<'a>(
        &'a self,
        sources: &'a str,
    ) -> Result<MultisigConsolidationRequest<'a>, JsValue> {
        Ok(MultisigConsolidationRequest {
            descriptor_text: &self.descriptor_text,
            sources_json: sources,
            destination_address: &self.destination_address,
            amount: decimal(&self.amount_sompi, "amount")?,
            fee: decimal(&self.fee_sompi, "fee")?,
            cosigner: self.cosigner,
            change_index_hint: self.change_index_hint,
        })
    }

    pub(super) fn encoded_sources(&self) -> Result<String, JsValue> {
        encode(&self.sources)
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum CovenantEncodingJson {
    Payload {
        payload_hex: String,
        tag_genesis: bool,
    },
    BoundGenesis,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CovenantPlanJson {
    wallet: WalletData,
    covenant_address: String,
    send_amount_sompi: String,
    fee_sompi: String,
    change_address: String,
    utxo_indices_csv: String,
    encoding: CovenantEncodingJson,
}

impl CovenantPlanJson {
    pub(super) fn request(&self) -> Result<CovenantBuildRequest<'_>, JsValue> {
        Ok(CovenantBuildRequest {
            wallet: &self.wallet,
            covenant_address: &self.covenant_address,
            send_amount: decimal(&self.send_amount_sompi, "send amount")?,
            fee: decimal(&self.fee_sompi, "fee")?,
            change_address: &self.change_address,
            utxo_indices_csv: &self.utxo_indices_csv,
            dust_policy: CovenantDustPolicy::Preserve,
            encoding: match &self.encoding {
                CovenantEncodingJson::Payload {
                    payload_hex,
                    tag_genesis,
                } => CovenantEncoding::Payload {
                    payload_hex,
                    tag_genesis: *tag_genesis,
                },
                CovenantEncodingJson::BoundGenesis => CovenantEncoding::BoundGenesis,
            },
        })
    }
}

/// Script, redeem and covenant-identity bytes shared by both thread planners.
struct ThreadScripts {
    covenant_script: Vec<u8>,
    redeem_script: Vec<u8>,
    covenant_id: [u8; 32],
}

impl ThreadScripts {
    fn decode(covenant_script_hex: &str, redeem_hex: &str, id_hex: &str) -> Result<Self, JsValue> {
        Ok(Self {
            covenant_script: bytes_hex(covenant_script_hex, "covenant script")?,
            redeem_script: bytes_hex(redeem_hex, "redeem script")?,
            covenant_id: fixed32(id_hex, "covenant id")?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GlobalThreadWithdrawalJson {
    thread_utxos: Vec<UtxoEntry>,
    covenant_script_public_key_hex: String,
    destination_script_public_key_hex: String,
    redeem_script_hex: String,
    covenant_id_hex: String,
    withdrawal_sompi: String,
    fee_sompi: String,
    csv_sequence: String,
    policy: GlobalThreadPolicy,
}

impl GlobalThreadWithdrawalJson {
    pub(super) fn plan<T>(
        &self,
        plan: impl FnOnce(GlobalThreadWithdrawalRequest<'_>) -> T,
    ) -> Result<T, JsValue> {
        let scripts = ThreadScripts::decode(
            &self.covenant_script_public_key_hex,
            &self.redeem_script_hex,
            &self.covenant_id_hex,
        )?;
        let destination_script = bytes_hex(
            &self.destination_script_public_key_hex,
            "destination script",
        )?;
        Ok(plan(GlobalThreadWithdrawalRequest {
            thread_utxos: &self.thread_utxos,
            covenant_script_public_key: &scripts.covenant_script,
            destination_script_public_key: &destination_script,
            redeem_script: &scripts.redeem_script,
            covenant_id: &scripts.covenant_id,
            withdrawal: decimal(&self.withdrawal_sompi, "withdrawal")?,
            fee: decimal(&self.fee_sompi, "fee")?,
            csv_sequence: decimal(&self.csv_sequence, "CSV sequence")?,
            policy: &self.policy,
        }))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GlobalThreadTopupJson {
    thread_utxo: UtxoEntry,
    wallet_utxos: Vec<UtxoEntry>,
    covenant_script_public_key_hex: String,
    redeem_script_hex: String,
    covenant_id_hex: String,
    fee_sompi: String,
    policy: GlobalThreadPolicy,
}

impl GlobalThreadTopupJson {
    pub(super) fn plan<T>(
        self,
        plan: impl FnOnce(GlobalThreadTopupRequest<'_>) -> T,
    ) -> Result<T, JsValue> {
        let scripts = ThreadScripts::decode(
            &self.covenant_script_public_key_hex,
            &self.redeem_script_hex,
            &self.covenant_id_hex,
        )?;
        let fee = decimal(&self.fee_sompi, "fee")?;
        Ok(plan(GlobalThreadTopupRequest {
            thread_utxo: self.thread_utxo,
            wallet_utxos: &self.wallet_utxos,
            covenant_script_public_key: &scripts.covenant_script,
            redeem_script: &scripts.redeem_script,
            covenant_id: &scripts.covenant_id,
            fee,
            policy: &self.policy,
        }))
    }
}
