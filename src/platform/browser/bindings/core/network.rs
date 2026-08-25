use wasm_bindgen::prelude::*;

use crate::network::{
    client::NetworkClient, health::ConnectionStatus, wrpc::operation::Operation, NetworkApi,
};

use super::js_error;

#[wasm_bindgen(js_name = KaspaNetworkClient)]
pub struct WasmNetworkClient {
    inner: NetworkClient,
}

#[wasm_bindgen(js_class = KaspaNetworkClient)]
impl WasmNetworkClient {
    pub async fn call(&self, operation_code: u8, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        let operation = Operation::from_code(operation_code)
            .ok_or_else(|| JsValue::from_str("unsupported wRPC operation code"))?;
        self.inner
            .call(operation, payload)
            .await
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }
}

#[wasm_bindgen(js_name = KaspaNetwork)]
pub struct WasmNetwork {
    inner: NetworkApi,
}

impl WasmNetwork {
    pub(crate) fn from_api(inner: NetworkApi) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen(js_class = KaspaNetwork)]
impl WasmNetwork {
    #[wasm_bindgen(js_name = networkId)]
    pub fn network_id(&self) -> String {
        format!("{:?}", self.inner.network_id()).to_ascii_lowercase()
    }

    pub fn endpoint(&self) -> String {
        self.inner.endpoint().to_owned()
    }

    pub fn status(&self) -> String {
        status_name(&self.inner.status()).to_owned()
    }

    pub fn client(&self) -> WasmNetworkClient {
        WasmNetworkClient {
            inner: self.inner.client(),
        }
    }

    pub async fn connect(&self) -> Result<String, JsValue> {
        let health = self.inner.connect().await.map_err(js_error)?;
        Ok(health_json(&health))
    }

    pub async fn health(&self) -> Result<String, JsValue> {
        let health = self.inner.health().await.map_err(js_error)?;
        Ok(health_json(&health))
    }

    pub async fn reconnect(&self) -> Result<String, JsValue> {
        let health = self.inner.reconnect().await.map_err(js_error)?;
        Ok(health_json(&health))
    }

    pub fn disconnect(&self) {
        self.inner.disconnect();
    }
}

fn status_name(status: &ConnectionStatus) -> &'static str {
    match status {
        ConnectionStatus::Disconnected => "disconnected",
        ConnectionStatus::Connecting => "connecting",
        ConnectionStatus::Connected => "connected",
        ConnectionStatus::Degraded => "degraded",
    }
}

fn health_json(health: &crate::network::health::NetworkHealth) -> String {
    let score = health.virtual_daa_score.map(|value| value.to_string());
    serde_json::json!({
        "status": status_name(&health.status),
        "endpoint": health.endpoint.clone(),
        "virtualDaaScore": score,
    })
    .to_string()
}
