//! Durable browser persistence for the lightweight indexer.
//!
//! IndexedDB stores one versioned, owned Rust state value per namespace. Live
//! Rust/WASM handles, callbacks, connection objects, and secret keys are never
//! serialized. Schema validation happens in the core before state is restored.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::{
    error::{Error, Result},
    indexer::storage::{IndexerPersistence, PersistedIndexerState, PersistenceFuture},
};

pub const INDEX_DB_NAME: &str = "kaspa-portal";
pub const INDEX_DB_VERSION: u32 = 1;
const INDEX_STORE: &str = "indexer-state";

#[wasm_bindgen(inline_js = r#"
function openPortalDb(dbName, version, storeName) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(dbName, version);
    open.onupgradeneeded = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains(storeName)) db.createObjectStore(storeName);
    };
    open.onerror = () => reject(open.error || new Error('IndexedDB open failed'));
    open.onsuccess = () => resolve(open.result);
  });
}
export async function kpIdbPut(dbName, version, storeName, key, value) {
  const db = await openPortalDb(dbName, version, storeName);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).put(value, key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { const e = tx.error; db.close(); reject(e || new Error('IndexedDB write failed')); };
    tx.onabort = () => { const e = tx.error; db.close(); reject(e || new Error('IndexedDB write aborted')); };
  });
}
export async function kpIdbGet(dbName, version, storeName, key) {
  const db = await openPortalDb(dbName, version, storeName);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).get(key);
    request.onsuccess = () => resolve(request.result === undefined ? null : request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB read failed'));
    tx.oncomplete = () => db.close();
    tx.onerror = () => { const e = tx.error; db.close(); reject(e || new Error('IndexedDB read transaction failed')); };
    tx.onabort = () => { const e = tx.error; db.close(); reject(e || new Error('IndexedDB read transaction aborted')); };
  });
}
export async function kpIdbDelete(dbName, version, storeName, key) {
  const db = await openPortalDb(dbName, version, storeName);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).delete(key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { const e = tx.error; db.close(); reject(e || new Error('IndexedDB delete failed')); };
    tx.onabort = () => { const e = tx.error; db.close(); reject(e || new Error('IndexedDB delete aborted')); };
  });
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = kpIdbPut)]
    fn idb_put(db: &str, version: u32, store: &str, key: &str, value: &str) -> Promise;
    #[wasm_bindgen(js_name = kpIdbGet)]
    fn idb_get(db: &str, version: u32, store: &str, key: &str) -> Promise;
    #[wasm_bindgen(js_name = kpIdbDelete)]
    fn idb_delete(db: &str, version: u32, store: &str, key: &str) -> Promise;
}

#[derive(Clone, Debug)]
pub struct IndexedDbIndexerStorage {
    namespace: String,
}

impl IndexedDbIndexerStorage {
    pub fn new(namespace: impl Into<String>) -> Result<Self> {
        let namespace = namespace.into();
        validate_namespace(&namespace)?;
        Ok(Self { namespace })
    }

    async fn read(&self) -> Result<Option<PersistedIndexerState>> {
        let value = await_promise(
            idb_get(
                INDEX_DB_NAME,
                INDEX_DB_VERSION,
                INDEX_STORE,
                &self.namespace,
            ),
            "load",
        )
        .await?;
        if value.is_null() || value.is_undefined() {
            return Ok(None);
        }
        let json = value
            .as_string()
            .ok_or_else(|| Error::Storage("IndexedDB indexer state is not a string".into()))?;
        let state: PersistedIndexerState = serde_json::from_str(&json)
            .map_err(|error| Error::Storage(format!("decode IndexedDB indexer state: {error}")))?;
        state.validate_schema()?;
        Ok(Some(state))
    }

    async fn write(&self, state: PersistedIndexerState) -> Result<()> {
        state.validate_schema()?;
        let json = serde_json::to_string(&state).map_err(|error| {
            Error::Storage(format!("serialize IndexedDB indexer state: {error}"))
        })?;
        await_promise(
            idb_put(
                INDEX_DB_NAME,
                INDEX_DB_VERSION,
                INDEX_STORE,
                &self.namespace,
                &json,
            ),
            "save",
        )
        .await?;
        Ok(())
    }

    async fn delete(&self) -> Result<()> {
        await_promise(
            idb_delete(
                INDEX_DB_NAME,
                INDEX_DB_VERSION,
                INDEX_STORE,
                &self.namespace,
            ),
            "clear",
        )
        .await?;
        Ok(())
    }
}

impl IndexerPersistence for IndexedDbIndexerStorage {
    fn load_state(&self) -> PersistenceFuture<'_, Option<PersistedIndexerState>> {
        Box::pin(self.read())
    }

    fn save_state(&self, state: PersistedIndexerState) -> PersistenceFuture<'_, ()> {
        Box::pin(self.write(state))
    }

    fn clear_state(&self) -> PersistenceFuture<'_, ()> {
        Box::pin(self.delete())
    }
}

fn validate_namespace(namespace: &str) -> Result<()> {
    if namespace.is_empty() || namespace.len() > 128 {
        return Err(Error::Storage(
            "IndexedDB namespace must be 1..=128 bytes".into(),
        ));
    }
    if !namespace
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(Error::Storage(
            "IndexedDB namespace contains unsupported characters".into(),
        ));
    }
    Ok(())
}

async fn await_promise(promise: Promise, operation: &str) -> Result<JsValue> {
    JsFuture::from(promise).await.map_err(|value| {
        Error::Storage(format!(
            "IndexedDB {operation} failed: {}",
            js_error(&value)
        ))
    })
}

fn js_error(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| js_sys::JSON::stringify(value).ok()?.as_string())
        .unwrap_or_else(|| "unknown browser error".into())
}
