//! Portal's native `wss://` transport must not depend on rustls's
//! process-level crypto provider. Applications routinely enable both rustls
//! backends (libp2p's QUIC uses aws-lc-rs, reqwest uses ring); rustls then
//! refuses to pick a default and panics inside the TLS handshake, which killed
//! every Portal connection in such apps. This crate enables both backends on
//! purpose, so every QA test runs in that configuration.

use kaspa_portal::{primitives::NetworkId, KaspaPortal};

#[tokio::test(flavor = "current_thread")]
async fn tls_handshake_runs_when_both_rustls_backends_are_enabled() {
    // A listener that accepts and drops connections: the TLS client is built
    // and the handshake starts, then fails as an ordinary connection error.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });

    let error = KaspaPortal::builder()
        .network(NetworkId::Mainnet)
        .endpoint(format!("wss://127.0.0.1:{port}"))
        .max_retries(0)
        .timeout_ms(5_000)
        .connect()
        .await
        .err()
        .expect("nothing speaks TLS on the local listener")
        .to_string();
    assert!(
        !error.contains("driver stopped"),
        "the TLS client panicked instead of failing the handshake: {error}"
    );
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "Portal must use its own provider, not install a process-wide one"
    );
}
