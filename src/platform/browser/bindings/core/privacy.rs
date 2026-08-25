use serde::Deserialize;
use wasm_bindgen::prelude::*;

use super::js_error;
use crate::{privacy::stealth, privacy::PrivacyApi};

#[wasm_bindgen(js_name = KaspaPrivacy)]
pub struct WasmPrivacy {
    inner: PrivacyApi,
}

impl WasmPrivacy {
    pub(crate) fn from_api(inner: PrivacyApi) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen(js_class = KaspaPrivacy)]
impl WasmPrivacy {
    #[wasm_bindgen(js_name = announcementAddress)]
    pub fn announcement_address(&self, prefix: &str) -> String {
        self.inner.stealth().announcement_address(prefix)
    }

    #[wasm_bindgen(js_name = decodeMetadata)]
    pub fn decode_metadata(&self, value: &str) -> Result<String, JsValue> {
        let metadata = self
            .inner
            .stealth()
            .decode_metadata(value)
            .map_err(js_error)?;
        Ok(metadata_json(&metadata))
    }

    #[wasm_bindgen(js_name = deriveMetadata)]
    pub fn derive_metadata(&self, kpub: &str) -> Result<String, JsValue> {
        let metadata = self
            .inner
            .stealth()
            .derive_metadata(kpub)
            .map_err(js_error)?;
        Ok(self.inner.stealth().encode_metadata(&metadata))
    }

    #[wasm_bindgen(js_name = encodeMetadata)]
    pub fn encode_metadata(&self, metadata_json: &str) -> Result<String, JsValue> {
        let value: BrowserStealthMeta = serde_json::from_str(metadata_json)
            .map_err(|error| JsValue::from_str(&format!("invalid metadata JSON: {error}")))?;
        let combined = format!("{}{}", value.scan_pubkey, value.spend_pubkey);
        let metadata = self
            .inner
            .stealth()
            .decode_metadata(&combined)
            .map_err(js_error)?;
        Ok(self.inner.stealth().encode_metadata(&metadata))
    }

    #[wasm_bindgen(js_name = generateStealthPayment)]
    pub fn generate_stealth_payment(
        &self,
        metadata_hex: &str,
        entropy_hex: &str,
    ) -> Result<String, JsValue> {
        let metadata = self
            .inner
            .stealth()
            .decode_metadata(metadata_hex)
            .map_err(js_error)?;
        let entropy = fixed32(entropy_hex, "entropy")?;
        let payment = self
            .inner
            .stealth()
            .generate_payment(&metadata, &entropy)
            .map_err(js_error)?;
        Ok(serde_json::json!({
            "oneTimePubkey": hex::encode(payment.one_time_pubkey),
            "ephemeralPubkey": hex::encode(payment.ephemeral_pubkey),
            "stealthIndex": payment.stealth_index,
            "viewTag": payment.view_tag,
        })
        .to_string())
    }

    #[wasm_bindgen(js_name = scanRawForPreimage)]
    pub fn scan_raw_for_preimage(
        &self,
        raw: &[u8],
        transaction_id_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let transaction_id = hex::decode(transaction_id_hex)
            .map_err(|error| JsValue::from_str(&format!("invalid transaction id: {error}")))?;
        let preimage = self
            .inner
            .stealth()
            .scan_raw_for_preimage(raw, &transaction_id);
        Ok(match preimage {
            Some(preimage) => JsValue::from_str(&hex::encode(preimage)),
            None => JsValue::NULL,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserStealthMeta {
    scan_pubkey: String,
    spend_pubkey: String,
}

fn metadata_json(metadata: &stealth::StealthMeta) -> String {
    serde_json::json!({
        "scanPubkey": hex::encode(stealth::x_only_pub(&metadata.scan_pubkey)),
        "spendPubkey": hex::encode(stealth::x_only_pub(&metadata.spend_pubkey)),
    })
    .to_string()
}

fn fixed32(value: &str, name: &str) -> Result<[u8; 32], JsValue> {
    let bytes = hex::decode(value)
        .map_err(|error| JsValue::from_str(&format!("invalid {name}: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{name} must be 32 bytes")))
}
