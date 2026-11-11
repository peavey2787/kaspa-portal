//! Server notifications that arrived before a caller asked for one, and
//! callers waiting for the next notification.

use std::collections::VecDeque;

use tokio::sync::oneshot;

use crate::network::error::NetworkError;

use super::super::websocket::MAX_QUEUED_NOTIFICATIONS;

/// Where one caller receives its frame or the error that ended its wait.
pub(super) type Reply = oneshot::Sender<Result<Vec<u8>, NetworkError>>;

#[derive(Default)]
pub(super) struct Notifications {
    pub(super) queued: VecDeque<Vec<u8>>,
    pub(super) waiters: VecDeque<Reply>,
}

impl Notifications {
    pub(super) fn has_waiters(&self) -> bool {
        !self.waiters.is_empty()
    }

    /// Answer a caller from the queue, or keep it waiting for the next frame.
    pub(super) fn wait(&mut self, waiter: Reply) {
        match self.queued.pop_front() {
            Some(frame) => {
                let _ = waiter.send(Ok(frame));
            }
            None => self.waiters.push_back(waiter),
        }
    }

    /// Hand a fresh notification to a waiting caller, or queue it.
    pub(super) fn deliver(&mut self, frame: Vec<u8>) -> Result<(), NetworkError> {
        let Err(frame) = self.send_to_waiter(frame) else {
            return Ok(());
        };
        if self.queued.len() >= MAX_QUEUED_NOTIFICATIONS {
            return Err(NetworkError::UnexpectedResponse(
                "Kaspa notification queue capacity exceeded".into(),
            ));
        }
        self.queued.push_back(frame);
        Ok(())
    }

    /// Hand queued notifications, oldest first, to callers that began waiting.
    pub(super) fn dispatch_queued(&mut self) {
        while let Some(frame) = self.queued.pop_front() {
            if let Err(frame) = self.send_to_waiter(frame) {
                self.queued.push_front(frame);
                return;
            }
        }
    }

    pub(super) fn fail_waiters(&mut self, error: &NetworkError) {
        while let Some(waiter) = self.waiters.pop_front() {
            let _ = waiter.send(Err(error.clone()));
        }
    }

    /// Give the frame to the first caller still listening, or return it.
    fn send_to_waiter(&mut self, frame: Vec<u8>) -> Result<(), Vec<u8>> {
        while let Some(waiter) = self.waiters.pop_front() {
            if waiter.send(Ok(frame.clone())).is_ok() {
                return Ok(());
            }
        }
        Err(frame)
    }
}
