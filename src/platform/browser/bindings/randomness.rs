use wasm_bindgen::prelude::*;

use crate::{
    primitives::NetworkId,
    randomness::{
        beacon::{BeaconRequest, BeaconResult},
        vrf::{VrfProof, VrfPublicKey, VrfSecretKey},
        RandomnessApi,
    },
};

#[wasm_bindgen(js_name = KaspaVrfSecretKey)]
pub struct WasmVrfSecretKey {
    inner: VrfSecretKey,
}

#[wasm_bindgen(js_class = KaspaVrfSecretKey)]
impl WasmVrfSecretKey {
    #[wasm_bindgen(constructor)]
    pub fn new(secret_hex: &str) -> core::result::Result<WasmVrfSecretKey, JsValue> {
        Ok(Self {
            inner: secret(secret_hex)?,
        })
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> String {
        hex::encode(self.inner.public_key().0)
    }

    pub fn prove(&self, input: &[u8]) -> core::result::Result<String, JsValue> {
        let result = crate::randomness::vrf::VrfApi::default()
            .prove(&self.inner, input)
            .map_err(|error| js(error.to_string()))?;
        serde_json::to_string(&result).map_err(|error| js(format!("encode VRF result: {error}")))
    }

    #[cfg(feature = "secret-export")]
    #[wasm_bindgen(js_name = exposeSecret)]
    pub fn expose_secret(&self) -> String {
        hex::encode(self.inner.expose_secret())
    }
}

#[wasm_bindgen(js_name = KaspaRandomness)]
pub struct WasmRandomness {
    inner: RandomnessApi,
}

impl WasmRandomness {
    pub(crate) fn new_inner() -> Self {
        Self {
            inner: RandomnessApi::new(crate::platform::curby_client()),
        }
    }

    pub(crate) fn from_api(inner: RandomnessApi) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen(js_class = KaspaRandomness)]
impl WasmRandomness {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmRandomness {
        Self::new_inner()
    }

    #[wasm_bindgen(js_name = observeKaspaBlock)]
    pub fn observe_kaspa_block(&self, evidence_json: &str) -> core::result::Result<(), JsValue> {
        let evidence = serde_json::from_str(evidence_json)
            .map_err(|error| js(format!("invalid Kaspa evidence: {error}")))?;
        self.inner
            .beacon()
            .observe_kaspa_block(evidence)
            .map_err(|error| js(error.to_string()))
    }

    #[wasm_bindgen(js_name = generateBeacon)]
    pub fn generate_beacon(&self, request_json: &str) -> core::result::Result<String, JsValue> {
        let request: BeaconRequest = serde_json::from_str(request_json)
            .map_err(|error| js(format!("invalid beacon request: {error}")))?;
        let result = self
            .inner
            .beacon()
            .generate(request)
            .map_err(|error| js(error.to_string()))?;
        serde_json::to_string(&result).map_err(|error| js(format!("encode beacon result: {error}")))
    }

    #[wasm_bindgen(js_name = verifyBeacon)]
    pub fn verify_beacon(&self, result_json: &str) -> core::result::Result<String, JsValue> {
        let result: BeaconResult = serde_json::from_str(result_json)
            .map_err(|error| js(format!("invalid beacon result: {error}")))?;
        let verification = self
            .inner
            .beacon()
            .verify(&result)
            .map_err(|error| js(error.to_string()))?;
        serde_json::to_string(&verification)
            .map_err(|error| js(format!("encode beacon verification: {error}")))
    }

    #[wasm_bindgen(js_name = generateLive)]
    pub async fn generate_live(
        &self,
        network: &str,
        kaspa_blocks: u32,
        use_curby: bool,
        context: &[u8],
    ) -> core::result::Result<String, JsValue> {
        let kaspa_blocks = usize::try_from(kaspa_blocks)
            .map_err(|_| js("kaspa block count does not fit this platform".into()))?;
        let result = self
            .inner
            .beacon()
            .generate_live(
                parse_network(network)?,
                kaspa_blocks,
                use_curby,
                context.to_vec(),
            )
            .await
            .map_err(|error| js(error.to_string()))?;
        serde_json::to_string(&result).map_err(|error| js(format!("encode beacon result: {error}")))
    }

    #[wasm_bindgen(js_name = generateVrfKeypair)]
    pub fn generate_vrf_keypair(&self) -> core::result::Result<WasmVrfSecretKey, JsValue> {
        let (secret, _) = self
            .inner
            .vrf()
            .generate_keypair()
            .map_err(|error| js(error.to_string()))?;
        Ok(WasmVrfSecretKey { inner: secret })
    }

    #[wasm_bindgen(js_name = vrfPublicKey)]
    pub fn vrf_public_key(&self, secret_hex: &str) -> core::result::Result<String, JsValue> {
        let secret = secret(secret_hex)?;
        Ok(hex::encode(secret.public_key().0))
    }

    #[wasm_bindgen(js_name = vrfProve)]
    pub fn vrf_prove(
        &self,
        secret_hex: &str,
        input: &[u8],
    ) -> core::result::Result<String, JsValue> {
        let secret = secret(secret_hex)?;
        let result = self
            .inner
            .vrf()
            .prove(&secret, input)
            .map_err(|error| js(error.to_string()))?;
        serde_json::to_string(&result).map_err(|error| js(format!("encode VRF result: {error}")))
    }

    #[wasm_bindgen(js_name = vrfVerify)]
    pub fn vrf_verify(
        &self,
        public_hex: &str,
        input: &[u8],
        proof_hex: &str,
    ) -> core::result::Result<String, JsValue> {
        let public = fixed32(public_hex, "VRF public key")?;
        let proof =
            hex::decode(proof_hex).map_err(|error| js(format!("invalid VRF proof: {error}")))?;
        let output = self
            .inner
            .vrf()
            .verify(&VrfPublicKey(public), input, &VrfProof(proof))
            .map_err(|error| js(error.to_string()))?;
        Ok(hex::encode(output.0))
    }
}

fn secret(value: &str) -> core::result::Result<VrfSecretKey, JsValue> {
    Ok(VrfSecretKey::from_bytes(fixed32(value, "VRF secret key")?))
}

fn fixed32(value: &str, name: &str) -> core::result::Result<[u8; 32], JsValue> {
    let bytes = hex::decode(value).map_err(|error| js(format!("invalid {name}: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| js(format!("{name} must be 32 bytes")))
}

fn parse_network(value: &str) -> core::result::Result<NetworkId, JsValue> {
    NetworkId::parse(value).map_err(js)
}

fn js(message: String) -> JsValue {
    JsValue::from_str(&message)
}
