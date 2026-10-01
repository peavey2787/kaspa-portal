use wasm_bindgen::prelude::*;

use crate::{chain::ChainApi, primitives::BlockHash};

use super::{encode, js_error};

fn parse_block_hash(hash_hex: &str) -> Result<BlockHash, JsValue> {
    let bytes = hex::decode(hash_hex)
        .map_err(|error| JsValue::from_str(&format!("invalid block hash: {error}")))?;
    let hash: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsValue::from_str("block hash must be 32 bytes"))?;
    Ok(BlockHash::new(hash))
}

#[wasm_bindgen(js_name = KaspaChain)]
pub struct WasmChain {
    inner: ChainApi,
}

impl WasmChain {
    pub(crate) fn from_api(inner: ChainApi) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen(js_class = KaspaChain)]
impl WasmChain {
    #[wasm_bindgen(js_name = virtualDaaScore)]
    pub async fn virtual_daa_score(&self) -> Result<js_sys::BigInt, JsValue> {
        self.inner
            .virtual_daa_score()
            .await
            .map(|score| crate::platform::browser::bigint::u64_to_bigint(score.get()))
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = blockRaw)]
    pub async fn block_raw(&self, hash_hex: &str) -> Result<Vec<u8>, JsValue> {
        self.inner
            .block_raw(&parse_block_hash(hash_hex)?)
            .await
            .map_err(js_error)
    }

    /// JSON `[{blockHash, daaScore, transactions: [{transactionId, payloadHex}]}]`
    /// for blocks accepted after `low_hash_hex` (one bounded node page).
    #[wasm_bindgen(js_name = blocksSince)]
    pub async fn blocks_since(&self, low_hash_hex: &str) -> Result<String, JsValue> {
        let blocks = self
            .inner
            .blocks_since(&parse_block_hash(low_hash_hex)?)
            .await
            .map_err(js_error)?;
        let blocks: Vec<_> = blocks
            .into_iter()
            .map(|block| {
                serde_json::json!({
                    "blockHash": block.block_hash,
                    "daaScore": block.daa_score.to_string(),
                    "transactions": block.transactions.into_iter().map(|tx| serde_json::json!({
                        "transactionId": tx.transaction_id,
                        "payloadHex": hex::encode(tx.payload),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        encode(&blocks)
    }

    pub async fn utxos(&self, address: &str) -> Result<String, JsValue> {
        encode(&self.inner.utxos(address).await.map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = utxosMany)]
    pub async fn utxos_many(&self, addresses_json: &str) -> Result<String, JsValue> {
        let addresses: Vec<String> = super::decode(addresses_json)?;
        encode(&self.inner.utxos_many(&addresses).await.map_err(js_error)?)
    }

    pub fn transaction(&self, txid: &str) -> Result<String, JsValue> {
        encode(&self.inner.transaction(txid).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = transactionRaw)]
    pub fn transaction_raw(&self, txid: &str) -> Result<String, JsValue> {
        encode(&self.inner.transaction_raw(txid).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = feeEstimate)]
    pub async fn fee_estimate(&self) -> Result<String, JsValue> {
        encode(&self.inner.fee_estimate().await.map_err(js_error)?)
    }
}
