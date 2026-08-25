use crate::randomness::source::curby::{CurbyIo, CurbyIoFuture};

pub struct BrowserCurbyIo;

impl CurbyIo for BrowserCurbyIo {
    fn now_ms(&self) -> Result<u64, String> {
        super::time::now_ms()
    }

    fn fetch_text<'a>(&'a self, url: &'a str) -> CurbyIoFuture<'a, String> {
        Box::pin(async move { super::fetch::fetch_text(url).await })
    }
}
