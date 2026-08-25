use wasm_bindgen::prelude::*;

use crate::{
    indexer::{
        matcher::MatchRule,
        query::{PageRequest, TransactionQuery},
        scanner::BlockBatch,
        storage::{IndexerSnapshot, PersistedIndexerState},
        IndexedBlock, IndexedTransaction, IndexerApi, IndexerConfig, IndexingMode,
        ReconciliationReport, SyncCheckpoint, VirtualChainDelta,
    },
    platform::browser::indexed_db::IndexedDbIndexerStorage,
};

#[wasm_bindgen(js_name = KaspaIndexer)]
pub struct WasmIndexer {
    inner: IndexerApi,
}

impl WasmIndexer {
    pub(crate) fn from_api(inner: IndexerApi) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen(js_class = KaspaIndexer)]
impl WasmIndexer {
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: Option<String>) -> core::result::Result<WasmIndexer, JsValue> {
        let config = match config_json {
            Some(value) => {
                let value: serde_json::Value = decode(&value)?;
                parse_browser_indexer_config(value)?
            }
            None => IndexerConfig::default(),
        };
        IndexerApi::with_clock(config, crate::platform::browser::time::now_ms)
            .map(Self::from_api)
            .map_err(js_error)
    }

    pub fn start(&self) -> core::result::Result<(), JsValue> {
        self.inner.start().map_err(js_error)
    }

    pub fn stop(&self) -> core::result::Result<(), JsValue> {
        self.inner.stop().map_err(js_error)
    }

    #[wasm_bindgen(js_name = watchAddress)]
    pub fn watch_address(&self, address: String) -> core::result::Result<js_sys::BigInt, JsValue> {
        self.inner
            .watch_address(address)
            .map(crate::platform::browser::bigint::u64_to_bigint)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = watchPayloadPrefix)]
    pub fn watch_payload_prefix(
        &self,
        value: &[u8],
    ) -> core::result::Result<js_sys::BigInt, JsValue> {
        matcher_id(self.inner.watch_payload_prefix(value.to_vec()))
    }

    #[wasm_bindgen(js_name = watchPayloadContains)]
    pub fn watch_payload_contains(
        &self,
        value: &[u8],
    ) -> core::result::Result<js_sys::BigInt, JsValue> {
        matcher_id(self.inner.watch_payload_contains(value.to_vec()))
    }

    #[wasm_bindgen(js_name = watchPayloadExact)]
    pub fn watch_payload_exact(
        &self,
        value: &[u8],
    ) -> core::result::Result<js_sys::BigInt, JsValue> {
        matcher_id(self.inner.watch_payload_exact(value.to_vec()))
    }

    #[wasm_bindgen(js_name = watchPayloadSuffix)]
    pub fn watch_payload_suffix(
        &self,
        value: &[u8],
    ) -> core::result::Result<js_sys::BigInt, JsValue> {
        matcher_id(self.inner.watch_payload_suffix(value.to_vec()))
    }

    #[wasm_bindgen(js_name = addMatcher)]
    pub fn add_matcher(&self, rule_json: &str) -> core::result::Result<js_sys::BigInt, JsValue> {
        let rule: MatchRule = decode(rule_json)?;
        matcher_id(self.inner.add_matcher(rule))
    }

    #[wasm_bindgen(js_name = removeMatcher)]
    pub fn remove_matcher(&self, id: &str) -> core::result::Result<bool, JsValue> {
        self.inner
            .remove_matcher(decimal(id, "matcher id")?)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = ingestTransaction)]
    pub fn ingest_transaction(&self, json: &str) -> core::result::Result<String, JsValue> {
        let value: IndexedTransaction = decode(json)?;
        encode(&self.inner.ingest_transaction(value).map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = ingestBlock)]
    pub fn ingest_block(&self, json: &str) -> core::result::Result<(), JsValue> {
        let value: IndexedBlock = decode(json)?;
        self.inner.ingest_block(value).map_err(js_error)
    }

    #[wasm_bindgen(js_name = ingestBlockBatch)]
    pub fn ingest_block_batch(&self, json: &str) -> core::result::Result<String, JsValue> {
        let value: BlockBatch = decode(json)?;
        encode(&self.inner.ingest_block_batch(value).map_err(js_error)?)
    }

    pub fn transaction(&self, txid: &str) -> core::result::Result<String, JsValue> {
        encode(&self.inner.transaction(txid).map_err(js_error)?)
    }

    pub fn transactions(&self, query_json: &str) -> core::result::Result<String, JsValue> {
        let query: TransactionQuery = decode(query_json)?;
        encode(&self.inner.transactions(query).map_err(js_error)?)
    }

    pub fn blocks(&self, page_json: &str) -> core::result::Result<String, JsValue> {
        let page: PageRequest = decode(page_json)?;
        encode(&self.inner.blocks(page).map_err(js_error)?)
    }

    pub fn matches(&self, page_json: &str) -> core::result::Result<String, JsValue> {
        let page: PageRequest = decode(page_json)?;
        encode(&self.inner.matches(page).map_err(js_error)?)
    }

    pub fn snapshot(&self) -> core::result::Result<String, JsValue> {
        encode(&self.inner.snapshot().map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = restoreSnapshot)]
    pub fn restore_snapshot(&self, json: &str) -> core::result::Result<(), JsValue> {
        let snapshot: IndexerSnapshot = decode(json)?;
        self.inner.restore_snapshot(snapshot).map_err(js_error)
    }

    pub fn metrics(&self) -> core::result::Result<String, JsValue> {
        encode(&self.inner.metrics().map_err(js_error)?)
    }

    pub fn health(&self) -> core::result::Result<String, JsValue> {
        encode(&self.inner.health().map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = drainEvents)]
    pub fn drain_events(&self) -> core::result::Result<String, JsValue> {
        encode(&self.inner.drain_events().map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = saveIndexedDb)]
    pub async fn save_indexed_db(&self, namespace: &str) -> core::result::Result<(), JsValue> {
        let storage = IndexedDbIndexerStorage::new(namespace).map_err(js_error)?;
        self.inner.save_to(&storage).await.map_err(js_error)
    }

    #[wasm_bindgen(js_name = loadIndexedDb)]
    pub async fn load_indexed_db(&self, namespace: &str) -> core::result::Result<bool, JsValue> {
        let storage = IndexedDbIndexerStorage::new(namespace).map_err(js_error)?;
        self.inner.restore_from(&storage).await.map_err(js_error)
    }

    #[wasm_bindgen(js_name = clearIndexedDb)]
    pub async fn clear_indexed_db(&self, namespace: &str) -> core::result::Result<(), JsValue> {
        let storage = IndexedDbIndexerStorage::new(namespace).map_err(js_error)?;
        self.inner.clear_persisted(&storage).await.map_err(js_error)
    }

    #[wasm_bindgen(js_name = persistedState)]
    pub fn persisted_state(&self) -> core::result::Result<String, JsValue> {
        encode(&self.inner.persisted_state().map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = restoreState)]
    pub fn restore_state(&self, json: &str) -> core::result::Result<(), JsValue> {
        let state: PersistedIndexerState = decode(json)?;
        self.inner.restore_state(state).map_err(js_error)
    }

    pub fn checkpoint(&self) -> core::result::Result<String, JsValue> {
        encode(&self.inner.checkpoint().map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = setCheckpoint)]
    pub fn set_checkpoint(&self, json: &str) -> core::result::Result<(), JsValue> {
        let checkpoint: SyncCheckpoint = decode(json)?;
        self.inner.set_checkpoint(checkpoint).map_err(js_error)
    }

    #[wasm_bindgen(js_name = applySyncBatches)]
    pub fn apply_sync_batches(
        &self,
        batches_json: &str,
        checkpoint_json: &str,
    ) -> core::result::Result<String, JsValue> {
        let batches: Vec<BlockBatch> = decode(batches_json)?;
        let checkpoint: SyncCheckpoint = decode(checkpoint_json)?;
        encode(
            &self
                .inner
                .apply_sync_batches(batches, checkpoint)
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = reconcileVirtualChain)]
    pub fn reconcile_virtual_chain(&self, json: &str) -> core::result::Result<String, JsValue> {
        let delta: VirtualChainDelta = decode(json)?;
        let report: ReconciliationReport = self
            .inner
            .reconcile_virtual_chain(delta)
            .map_err(js_error)?;
        encode(&report)
    }

    pub fn clear(&self) -> core::result::Result<(), JsValue> {
        self.inner.clear().map_err(js_error)
    }
}

pub(super) fn parse_browser_indexer_config(
    value: serde_json::Value,
) -> core::result::Result<IndexerConfig, JsValue> {
    let object = value
        .as_object()
        .ok_or_else(|| JsValue::from_str("indexer config must be a JSON object"))?;
    let mut config = IndexerConfig::default();
    for (name, value) in object {
        match name.as_str() {
            "mode" => config.mode = parse_indexing_mode(value)?,
            "maxTransactions" | "max_transactions" => {
                config.max_transactions = parse_usize(value, name)?
            }
            "maxBlocks" | "max_blocks" => config.max_blocks = parse_usize(value, name)?,
            "maxMatches" | "max_matches" => config.max_matches = parse_usize(value, name)?,
            "dedupeWindow" | "dedupe_window" => config.dedupe_window = parse_usize(value, name)?,
            "scannerStaleAfterMs" | "scanner_stale_after_ms" => {
                config.scanner_stale_after_ms = parse_decimal_value(value, name)?
            }
            "transactionTtlMs" | "transaction_ttl_ms" => {
                config.transaction_ttl_ms = parse_decimal_value(value, name)?
            }
            "maxPayloadBytes" | "max_payload_bytes" => {
                config.max_payload_bytes = parse_usize(value, name)?
            }
            "maxAddressesPerTransaction" | "max_addresses_per_transaction" => {
                config.max_addresses_per_transaction = parse_usize(value, name)?
            }
            "maxQueryPage" | "max_query_page" => config.max_query_page = parse_usize(value, name)?,
            _ => {
                return Err(JsValue::from_str(&format!(
                    "unsupported indexer config field: {name}"
                )))
            }
        }
    }
    Ok(config)
}

fn parse_indexing_mode(value: &serde_json::Value) -> core::result::Result<IndexingMode, JsValue> {
    if let Some(mode) = value.as_str() {
        return match mode {
            "all" => Ok(IndexingMode::All),
            "transactions" => Ok(IndexingMode::Transactions),
            "matches" => Ok(IndexingMode::Matches),
            "blocks" => Ok(IndexingMode::Blocks),
            _ => Err(JsValue::from_str("unsupported indexer mode")),
        };
    }
    if let Ok(mode) = serde_json::from_value::<IndexingMode>(value.clone()) {
        return Ok(mode);
    }
    let object = value
        .as_object()
        .ok_or_else(|| JsValue::from_str("indexer mode must be a string or custom-mode object"))?;
    let transactions = object
        .get("transactions")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| JsValue::from_str("custom indexer mode requires transactions boolean"))?;
    let matches = object
        .get("matches")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| JsValue::from_str("custom indexer mode requires matches boolean"))?;
    let blocks = object
        .get("blocks")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| JsValue::from_str("custom indexer mode requires blocks boolean"))?;
    if object.len() != 3 {
        return Err(JsValue::from_str(
            "custom indexer mode accepts only transactions, matches, and blocks",
        ));
    }
    Ok(IndexingMode::Custom {
        transactions,
        matches,
        blocks,
    })
}

fn parse_usize(value: &serde_json::Value, name: &str) -> core::result::Result<usize, JsValue> {
    let number = value
        .as_u64()
        .ok_or_else(|| JsValue::from_str(&format!("{name} must be an unsigned integer")))?;
    usize::try_from(number)
        .map_err(|_| JsValue::from_str(&format!("{name} exceeds the platform usize range")))
}

fn parse_decimal_value(
    value: &serde_json::Value,
    name: &str,
) -> core::result::Result<u64, JsValue> {
    let text = value
        .as_str()
        .ok_or_else(|| JsValue::from_str(&format!("{name} must be a decimal string")))?;
    decimal(text, name)
}

fn matcher_id(value: crate::Result<u64>) -> core::result::Result<js_sys::BigInt, JsValue> {
    value
        .map(crate::platform::browser::bigint::u64_to_bigint)
        .map_err(js_error)
}

fn decimal(value: &str, name: &str) -> core::result::Result<u64, JsValue> {
    crate::primitives::serialization::decimal_u64::parse_canonical_decimal(value)
        .map_err(|error| JsValue::from_str(&format!("invalid {name}: {error}")))
}

fn decode<T: serde::de::DeserializeOwned>(json: &str) -> core::result::Result<T, JsValue> {
    serde_json::from_str(json).map_err(|error| JsValue::from_str(&format!("invalid JSON: {error}")))
}

fn encode<T: serde::Serialize>(value: &T) -> core::result::Result<String, JsValue> {
    serde_json::to_string(value)
        .map_err(|error| JsValue::from_str(&format!("JSON encode failed: {error}")))
}

fn js_error(error: crate::error::Error) -> JsValue {
    JsValue::from_str(&error.to_string())
}
