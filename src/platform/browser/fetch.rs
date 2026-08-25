#[cfg(target_arch = "wasm32")]
pub async fn fetch_text(url: &str) -> Result<String, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    let window = web_sys::window().ok_or("window unavailable")?;
    let response = JsFuture::from(window.fetch_with_str(url))
        .await
        .map_err(|e| format!("fetch failed: {e:?}"))?;
    let response: web_sys::Response = response.dyn_into().map_err(|_| "invalid fetch response")?;
    if !response.ok() {
        return Err(format!("HTTP {}", response.status()));
    }
    let promise = response
        .text()
        .map_err(|e| format!("response.text failed: {e:?}"))?;
    let value = JsFuture::from(promise)
        .await
        .map_err(|e| format!("response.text rejected: {e:?}"))?;
    value
        .as_string()
        .ok_or_else(|| "response text was not a string".into())
}
#[cfg(not(target_arch = "wasm32"))]
pub async fn fetch_text(_url: &str) -> Result<String, String> {
    Err("browser fetch unavailable on native target".into())
}
