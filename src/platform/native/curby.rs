use crate::randomness::source::curby::{CurbyIo, CurbyIoFuture};

pub struct NativeCurbyIo;

impl CurbyIo for NativeCurbyIo {
    fn now_ms(&self) -> Result<u64, String> {
        super::time::now_ms()
    }

    fn fetch_text<'a>(&'a self, url: &'a str) -> CurbyIoFuture<'a, String> {
        Box::pin(async move {
            let response = reqwest::Client::new()
                .get(url)
                .send()
                .await
                .map_err(|error| error.to_string())?;
            if !response.status().is_success() {
                return Err(format!("HTTP {}", response.status()));
            }
            response.text().await.map_err(|error| error.to_string())
        })
    }
}
