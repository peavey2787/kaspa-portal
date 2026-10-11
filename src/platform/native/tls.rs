//! TLS client for `wss://` nodes, pinned to the ring crypto provider.
//!
//! rustls otherwise falls back to a process-level provider and panics when an
//! application enables both of its backends (for example libp2p's QUIC with
//! aws-lc-rs next to reqwest with ring). Building the configuration with an
//! explicit provider keeps Portal's transport independent of what else the
//! application links.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use tokio_tungstenite::Connector;

use crate::network::error::NetworkError;

/// A rustls connector trusting the Mozilla root set through ring.
pub(super) fn connector() -> Result<Connector, NetworkError> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| NetworkError::ConnectionFailed(format!("TLS configuration: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}
