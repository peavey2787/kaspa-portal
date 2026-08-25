use wasm_bindgen::prelude::*;

use crate::wallet::{account::derivation::WalletData, mnemonic::bip39, WalletApi};

use super::{decode, encode, js_error};

#[wasm_bindgen(js_name = KaspaWallet)]
pub struct WasmWallet {
    inner: WalletApi,
}

impl WasmWallet {
    pub(crate) fn from_api(inner: WalletApi) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen(js_class = KaspaWallet)]
impl WasmWallet {
    #[wasm_bindgen(js_name = importKpub)]
    pub fn import_kpub(&self, kpub: &str) -> Result<String, JsValue> {
        encode(&self.inner.import_kpub(kpub).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = importKpubRaw)]
    pub fn import_kpub_raw(&self, payload: &[u8]) -> Result<String, JsValue> {
        encode(&self.inner.import_kpub_raw(payload).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = extendAddresses)]
    pub fn extend_addresses(
        &self,
        wallet_json: &str,
        receive: u32,
        change: u32,
    ) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        encode(
            &self
                .inner
                .extend_addresses(&wallet, receive, change)
                .map_err(js_error)?,
        )
    }

    pub async fn utxos(&self, wallet_json: &str) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        encode(&self.inner.utxos(&wallet).await.map_err(js_error)?)
    }

    pub async fn balance(&self, wallet_json: &str) -> Result<String, JsValue> {
        let wallet: WalletData = decode(wallet_json)?;
        let balance = self.inner.balance(&wallet).await.map_err(js_error)?;
        Ok(serde_json::json!({
            "totalSompi": balance.total_sompi.to_string(),
            "totalKasDisplay": kas_display(balance.total_sompi),
            "utxoCount": balance.utxo_count,
            "fundedAddresses": balance.funded_addresses,
            "fundedReceiveIndices": balance.funded_receive_indices,
            "fundedChangeIndices": balance.funded_change_indices,
        })
        .to_string())
    }

    #[wasm_bindgen(js_name = mnemonic12FromEntropy)]
    pub fn mnemonic_12_from_entropy(&self, entropy: &[u8]) -> Result<String, JsValue> {
        let entropy: [u8; 16] = entropy
            .try_into()
            .map_err(|_| JsValue::from_str("12-word mnemonic entropy must be 16 bytes"))?;
        let mnemonic = self.inner.mnemonic_12_from_entropy(&entropy);
        Ok(mnemonic_json(&mnemonic.indices))
    }

    #[wasm_bindgen(js_name = mnemonic24FromEntropy)]
    pub fn mnemonic_24_from_entropy(&self, entropy: &[u8]) -> Result<String, JsValue> {
        let entropy: [u8; 32] = entropy
            .try_into()
            .map_err(|_| JsValue::from_str("24-word mnemonic entropy must be 32 bytes"))?;
        let mnemonic = self.inner.mnemonic_24_from_entropy(&entropy);
        Ok(mnemonic_json(&mnemonic.indices))
    }

    pub fn prefix(&self) -> String {
        self.inner.prefix().to_owned()
    }
}

fn mnemonic_json(indices: &[u16]) -> String {
    let words = indices
        .iter()
        .map(|index| bip39::index_to_word(*index))
        .collect::<Vec<_>>();
    serde_json::json!({
        "indices": indices,
        "words": words,
        "phrase": words.join(" "),
    })
    .to_string()
}

fn kas_display(sompi: u64) -> String {
    let whole = sompi / 100_000_000;
    let fractional = sompi % 100_000_000;
    format!("{whole}.{fractional:08}")
}
