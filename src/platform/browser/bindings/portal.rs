use wasm_bindgen::prelude::*;

use super::{
    WasmChain, WasmContract, WasmIndexer, WasmNetwork, WasmPrivacy, WasmRandomness,
    WasmTransaction, WasmWallet,
};
use crate::{primitives::NetworkId, KaspaPortal};

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct BrowserPortalConfig {
    network: Option<String>,
    endpoint: Option<String>,
    timeout_ms: Option<String>,
    max_retries: Option<u8>,
    indexer: Option<serde_json::Value>,
}

/// Browser entry point. All consensus/security work remains in the Rust domains;
/// this object only creates thin target-specific wrappers around those domains.
#[wasm_bindgen(js_name = KaspaPortal)]
pub struct WasmKaspaPortal {
    inner: KaspaPortal,
}

#[wasm_bindgen(js_class = KaspaPortal)]
impl WasmKaspaPortal {
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: Option<String>) -> Result<WasmKaspaPortal, JsValue> {
        let config = match config_json {
            Some(value) => serde_json::from_str::<BrowserPortalConfig>(&value)
                .map_err(|error| js(format!("invalid portal config: {error}")))?,
            None => BrowserPortalConfig::default(),
        };
        let mut builder = KaspaPortal::builder();
        if let Some(network) = config.network.as_deref() {
            builder = builder.network(parse_network(network)?);
        }
        if let Some(endpoint) = config.endpoint {
            builder = builder.endpoint(endpoint);
        }
        if let Some(timeout) = config.timeout_ms.as_deref() {
            builder = builder.timeout_ms(parse_decimal(timeout, "timeoutMs")?);
        }
        if let Some(retries) = config.max_retries {
            builder = builder.max_retries(retries);
        }
        if let Some(indexer) = config.indexer {
            builder = builder.indexer(super::indexer::parse_browser_indexer_config(indexer)?);
        }
        let inner = builder.build().map_err(|error| js(error.to_string()))?;
        Ok(Self { inner })
    }

    pub fn config(&self) -> String {
        let config = self.inner.config();
        serde_json::json!({
            "network": format!("{:?}", config.network).to_ascii_lowercase(),
            "endpoint": config.endpoint.clone(),
            "timeoutMs": config.timeout_ms.to_string(),
            "maxRetries": config.max_retries,
            "indexer": config.indexer.clone(),
        })
        .to_string()
    }

    pub async fn connect(&self) -> Result<String, JsValue> {
        let health = self
            .inner
            .connect()
            .await
            .map_err(|error| js(error.to_string()))?;
        let score = health.virtual_daa_score.map(|value| value.to_string());
        Ok(serde_json::json!({
            "status": format!("{:?}", health.status).to_ascii_lowercase(),
            "endpoint": health.endpoint,
            "virtualDaaScore": score,
        })
        .to_string())
    }

    pub fn disconnect(&self) -> Result<(), JsValue> {
        self.inner
            .disconnect()
            .map_err(|error| js(error.to_string()))
    }

    pub fn network(&self) -> Result<WasmNetwork, JsValue> {
        self.inner
            .network()
            .cloned()
            .map(WasmNetwork::from_api)
            .map_err(|error| js(error.to_string()))
    }

    pub fn chain(&self) -> Result<WasmChain, JsValue> {
        self.inner
            .chain()
            .cloned()
            .map(WasmChain::from_api)
            .map_err(|error| js(error.to_string()))
    }

    pub fn wallet(&self) -> WasmWallet {
        WasmWallet::from_api(self.inner.wallet().clone())
    }
    pub fn transaction(&self) -> WasmTransaction {
        WasmTransaction::from_api(self.inner.transaction().clone())
    }
    pub fn contract(&self) -> WasmContract {
        WasmContract::from_api(*self.inner.contract())
    }
    pub fn privacy(&self) -> WasmPrivacy {
        WasmPrivacy::from_api(*self.inner.privacy())
    }
    pub fn indexer(&self) -> WasmIndexer {
        WasmIndexer::from_api(self.inner.indexer().clone())
    }
    pub fn randomness(&self) -> WasmRandomness {
        WasmRandomness::from_api(self.inner.randomness().clone())
    }
}

fn parse_network(value: &str) -> Result<NetworkId, JsValue> {
    NetworkId::parse(value).map_err(js)
}

fn parse_decimal(value: &str, name: &str) -> Result<u64, JsValue> {
    crate::primitives::serialization::decimal_u64::parse_canonical_decimal(value)
        .map_err(|error| js(format!("invalid {name}: {error}")))
}

fn js(message: String) -> JsValue {
    JsValue::from_str(&message)
}
