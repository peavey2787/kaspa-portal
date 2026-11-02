use super::*;

struct TestIo;
impl CurbyIo for TestIo {
    fn now_ms(&self) -> Result<u64, String> {
        Ok(1_000)
    }
    fn fetch_text<'a>(&'a self, _url: &'a str) -> CurbyIoFuture<'a, String> {
        Box::pin(async { Err("network disabled in unit test".into()) })
    }
}

fn client() -> CurbyClient {
    CurbyClient::new(Arc::new(TestIo))
}

fn evidence(retrieved_at_ms: u64) -> CurbyEvidence {
    CurbyEvidence {
        round: "7".into(),
        value: vec![0x42; 32],
        raw_response_hash: [0x24; 32],
        retrieved_at_ms,
        verification: CurbyVerification::RawApiUnverified,
    }
}

#[test]
fn parses_hex_result() {
    let body = r#"{"round":7,"result":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}"#;
    let parsed = parse_response(body, 100).unwrap();
    assert_eq!(parsed.round, "7");
    assert_eq!(parsed.value.len(), 32);
    assert_eq!(parsed.verification, CurbyVerification::RawApiUnverified);
}

#[test]
fn refresh_window_is_reserved_before_network_io() {
    let client = client();
    assert_eq!(client.reserve_or_cached(1_000).unwrap(), None);
    let error = client.reserve_or_cached(1_001).unwrap_err();
    assert!(error.contains("one-minute rate limit"));
}

#[test]
fn cache_is_reused_inside_one_minute_window() {
    let client = client();
    {
        let mut state = client.state.lock().unwrap();
        state.evidence = Some(evidence(10_000));
        state.last_attempt_ms = Some(10_000);
    }
    let cached = client
        .reserve_or_cached(10_000 + MIN_REFRESH_MS - 1)
        .unwrap();
    assert_eq!(cached, Some(evidence(10_000)));
}

#[test]
fn refresh_is_allowed_after_one_minute() {
    let client = client();
    {
        let mut state = client.state.lock().unwrap();
        state.evidence = Some(evidence(10_000));
        state.last_attempt_ms = Some(10_000);
    }
    let cached = client.reserve_or_cached(10_000 + MIN_REFRESH_MS).unwrap();
    assert_eq!(cached, None);
}
