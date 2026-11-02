use crate::{network::resolver, primitives::NetworkId};

#[test]
fn query_targets_the_tls_borsh_endpoint_for_the_network() {
    assert_eq!(
        resolver::query_url("https://eric.kaspa.stream", NetworkId::Testnet(10)),
        "https://eric.kaspa.stream/v2/kaspa/testnet-10/tls/wrpc/borsh"
    );
    assert_eq!(
        resolver::query_url("https://luke.kaspa.blue", NetworkId::Mainnet),
        "https://luke.kaspa.blue/v2/kaspa/mainnet/tls/wrpc/borsh"
    );
}

#[test]
fn only_tls_endpoints_are_accepted() {
    assert_eq!(
        resolver::parse_endpoint(
            r#"{"uid":"a1","url":"wss://node.example/kaspa/testnet-10/wrpc/borsh"}"#
        )
        .unwrap(),
        "wss://node.example/kaspa/testnet-10/wrpc/borsh"
    );
    let malformed = "resolver returned a non-TLS or malformed endpoint: ";
    for (body, expected) in [
        (
            r#"{"url":"ws://plain.example"}"#,
            format!("{malformed}ws://plain.example"),
        ),
        (
            r#"{"url":"https://node.example"}"#,
            format!("{malformed}https://node.example"),
        ),
        (r#"{"url":"wss://"}"#, format!("{malformed}wss://")),
        (r#"{"url":"wss://a b"}"#, format!("{malformed}wss://a b")),
        (
            r#"{"endpoint":"wss://node.example"}"#,
            "resolver response has no url".into(),
        ),
        (
            "not json",
            "resolver response: expected ident at line 1 column 2".into(),
        ),
    ] {
        crate::test_support::assert_err(
            &resolver::parse_endpoint(body),
            &format!("InvalidEncoding({expected:?})"),
        );
    }
}

#[test]
fn endpoints_are_deduplicated_in_answer_order() {
    let unique = resolver::unique_endpoints([
        "wss://b".to_owned(),
        "wss://a".to_owned(),
        "wss://b".to_owned(),
    ]);
    assert_eq!(unique, vec!["wss://b".to_owned(), "wss://a".to_owned()]);
}
