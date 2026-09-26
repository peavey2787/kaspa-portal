//! Kaspa notification subscriptions with one API on native and browser hosts.
//! The injected transport owns the socket: native hosts share the persistent
//! wRPC connection (subscriptions replay after reconnect); browser hosts use a
//! dedicated persistent notification socket.

use super::NetworkApi;
use crate::{
    error::{Error, Result},
    network::{
        codec::requests::subscription,
        error::NetworkError,
        wrpc::{
            block_added::OwnedBlockAddedNotification,
            notification::{self, Notification},
            response::{self, ResponseKind},
        },
    },
};

fn network(error: NetworkError) -> Error {
    Error::Network(error.to_string())
}

impl NetworkApi {
    /// Subscribe to Kaspa BlockAdded notifications.
    pub async fn subscribe_block_added(&self) -> Result<()> {
        self.subscribe_payload(subscription::block_added_payload().map_err(network)?)
            .await
    }

    /// Subscribe to UTXO changes for `addresses` (additive).
    pub async fn subscribe_utxos_changed(&self, addresses: &[String]) -> Result<()> {
        self.subscribe_payload(subscription::utxos_changed_payload(addresses).map_err(network)?)
            .await
    }

    /// Subscribe to virtual DAA score changes.
    pub async fn subscribe_virtual_daa_score_changed(&self) -> Result<()> {
        self.subscribe_payload(subscription::virtual_daa_score_changed_payload().map_err(network)?)
            .await
    }

    /// Next decoded notification of a subscribed kind.
    pub async fn next_notification(&self) -> Result<Notification> {
        loop {
            let frame = self.next_frame().await?;
            if !is_notification(&frame)? {
                continue;
            }
            if let Some(value) = notification::decode(&frame).map_err(network)? {
                return Ok(value);
            }
        }
    }

    /// Next BlockAdded notification; other notification kinds are skipped.
    pub async fn next_block_added(&self) -> Result<OwnedBlockAddedNotification> {
        loop {
            if let Notification::BlockAdded(block) = self.next_notification().await? {
                return Ok(block);
            }
        }
    }

    async fn subscribe_payload(&self, payload: Vec<u8>) -> Result<()> {
        self.client
            .subscribe(&payload)
            .await
            .map(|_| ())
            .map_err(network)
    }

    async fn next_frame(&self) -> Result<Vec<u8>> {
        self.client.next_notification().await.map_err(network)
    }
}

/// Subscription acknowledgements share the socket; skip them, surface errors.
fn is_notification(frame: &[u8]) -> Result<bool> {
    let decoded = response::decode(frame).map_err(network)?;
    match decoded.kind {
        ResponseKind::Notification if decoded.id.is_none() => Ok(true),
        ResponseKind::Error(code) => Err(Error::Network(format!(
            "Kaspa subscription failed: kind={code}"
        ))),
        _ => Ok(false),
    }
}
