use std::collections::VecDeque;
use std::future::pending;
use std::mem;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures_util::SinkExt;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Message};

use crate::network::{
    error::NetworkError,
    wrpc::{
        operation::Operation,
        request::{self, WrpcRequest},
        response::{self, ResponseKind},
    },
};

use super::websocket::{
    sleep_connect_backoff, ActiveCall, DriverCommand, NativeStream, QueuedCall, NEXT_REQUEST_ID,
};
use super::websocket_io::{receive_binary, validate_response};

mod notifications;

use notifications::Notifications;

/// The socket and the one request it may be answering. A request can only be
/// in flight on a live socket, so a lost socket always takes its request with it.
enum Link {
    Down,
    Idle(NativeStream),
    Busy(NativeStream, ActiveCall),
}

impl Link {
    fn up(stream: NativeStream, active: Option<ActiveCall>) -> Self {
        match active {
            Some(call) => Self::Busy(stream, call),
            None => Self::Idle(stream),
        }
    }
}

/// What woke the driver.
enum Event {
    Stop,
    Wake,
    Command(DriverCommand),
    Frame(Result<Vec<u8>, NetworkError>),
    Timeout,
}

/// Whether the driver may wait for the next event, or must first look again at
/// the queue because the last attempt to start a request changed the link.
enum Progress {
    Wait,
    Retry,
}

struct Driver {
    endpoint: String,
    timeout: Duration,
    max_retries: u8,
    link: Link,
    subscriptions: Vec<Vec<u8>>,
    queued_calls: VecDeque<QueuedCall>,
    notifications: Notifications,
}

pub(super) async fn run_driver(
    endpoint: String,
    timeout: Duration,
    max_retries: u8,
    mut commands: mpsc::Receiver<DriverCommand>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut driver = Driver {
        endpoint,
        timeout,
        max_retries,
        link: Link::Down,
        subscriptions: Vec::new(),
        queued_calls: VecDeque::new(),
        notifications: Notifications::default(),
    };
    while !*shutdown.borrow() {
        driver.notifications.dispatch_queued();
        driver.connect_when_needed().await;
        if matches!(driver.start_next_call().await, Progress::Retry) {
            continue;
        }
        match next_event(&mut driver.link, &mut commands, &mut shutdown).await {
            Event::Stop => break,
            Event::Wake => {}
            Event::Command(command) => driver.handle_command(command),
            Event::Frame(frame) => driver.receive(frame),
            Event::Timeout => driver.time_out(),
        }
    }
    driver.stop();
}

async fn next_event(
    link: &mut Link,
    commands: &mut mpsc::Receiver<DriverCommand>,
    shutdown: &mut watch::Receiver<bool>,
) -> Event {
    let (stream, deadline) = match link {
        Link::Down => (None, None),
        Link::Idle(stream) => (Some(stream), None),
        Link::Busy(stream, call) => (Some(stream), Some(call.deadline)),
    };
    tokio::select! {
        changed = shutdown.changed() => {
            if shutdown_requested(changed, shutdown) {
                Event::Stop
            } else {
                Event::Wake
            }
        }
        command = commands.recv() => command.map_or(Event::Stop, Event::Command),
        frame = receive_from(stream) => Event::Frame(frame),
        () = wait_for_deadline(deadline) => Event::Timeout,
    }
}

impl Driver {
    async fn connect_when_needed(&mut self) {
        let wanted = !self.queued_calls.is_empty() || self.notifications.has_waiters();
        if !matches!(self.link, Link::Down) || !wanted {
            return;
        }
        match establish_stream(
            &self.endpoint,
            self.timeout,
            self.max_retries,
            &self.subscriptions,
            &mut self.notifications,
        )
        .await
        {
            Ok(stream) => self.link = Link::Idle(stream),
            Err(error) => {
                fail_all_queued_calls(&mut self.queued_calls, &error);
                self.notifications.fail_waiters(&error);
            }
        }
    }

    async fn start_next_call(&mut self) -> Progress {
        let link = mem::replace(&mut self.link, Link::Down);
        let Link::Idle(mut stream) = link else {
            self.link = link;
            return Progress::Wait;
        };
        let Some(call) = self.queued_calls.pop_front() else {
            self.link = Link::Idle(stream);
            return Progress::Wait;
        };
        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let bytes = match encode_call(&call, request_id) {
            Ok(bytes) => bytes,
            Err(error) => {
                // A request that cannot be encoded is that caller's error alone;
                // the socket and every other caller are unaffected.
                let _ = call.response.send(Err(error));
                self.link = Link::Idle(stream);
                return Progress::Retry;
            }
        };
        if stream.send(Message::Binary(bytes.into())).await.is_err() {
            let error = NetworkError::SendFailed;
            let _ = call.response.send(Err(error.clone()));
            self.notifications.fail_waiters(&error);
            return Progress::Retry;
        }
        self.link = Link::Busy(
            stream,
            ActiveCall {
                request_id,
                operation: call.operation,
                payload: call.payload,
                response: call.response,
                deadline: Instant::now() + self.timeout,
            },
        );
        Progress::Wait
    }

    fn handle_command(&mut self, command: DriverCommand) {
        match command {
            DriverCommand::Call {
                operation,
                payload,
                response,
            } => self.queued_calls.push_back(QueuedCall {
                operation,
                payload,
                response,
            }),
            DriverCommand::NextNotification { response } => self.notifications.wait(response),
        }
    }

    fn receive(&mut self, frame: Result<Vec<u8>, NetworkError>) {
        let (stream, mut active) = match mem::replace(&mut self.link, Link::Down) {
            // Frames are only read from a live socket.
            Link::Down => return,
            Link::Idle(stream) => (stream, None),
            Link::Busy(stream, call) => (stream, Some(call)),
        };
        let handled = frame.and_then(|frame| {
            handle_received_frame(
                frame,
                &mut active,
                &mut self.subscriptions,
                &mut self.notifications,
            )
        });
        match handled {
            Ok(()) => self.link = Link::up(stream, active),
            Err(error) => {
                fail_active_call(active, &error);
                self.notifications.fail_waiters(&error);
            }
        }
    }

    fn time_out(&mut self) {
        match mem::replace(&mut self.link, Link::Down) {
            Link::Busy(_, call) => {
                let error = NetworkError::ResponseTimeout;
                fail_active_call(Some(call), &error);
                self.notifications.fail_waiters(&error);
                // The timed-out response may still arrive later. Dropping the
                // socket means it can never be mistaken for a later request's.
            }
            link => self.link = link,
        }
    }

    fn stop(mut self) {
        let error = NetworkError::ConnectionFailed("Kaspa wRPC driver stopped".into());
        if let Link::Busy(_, call) = self.link {
            fail_active_call(Some(call), &error);
        }
        fail_all_queued_calls(&mut self.queued_calls, &error);
        self.notifications.fail_waiters(&error);
    }
}

fn encode_call(call: &QueuedCall, request_id: u64) -> Result<Vec<u8>, NetworkError> {
    request::encode(&WrpcRequest {
        id: request_id,
        operation: call.operation,
        payload: &call.payload,
    })
}

fn shutdown_requested(
    changed: Result<(), tokio::sync::watch::error::RecvError>,
    shutdown: &watch::Receiver<bool>,
) -> bool {
    changed.is_err() || *shutdown.borrow()
}

fn handle_received_frame(
    frame: Vec<u8>,
    active_call: &mut Option<ActiveCall>,
    subscriptions: &mut Vec<Vec<u8>>,
    notifications: &mut Notifications,
) -> Result<(), NetworkError> {
    let decoded = response::decode(&frame)?;
    if decoded.id.is_none() {
        if decoded.kind != ResponseKind::Notification {
            return Err(NetworkError::UnexpectedResponse(
                "Kaspa server frame without request id was not marked as a notification".into(),
            ));
        }
        return notifications.deliver(frame);
    }

    let active = active_call.take().ok_or_else(|| {
        NetworkError::UnexpectedResponse(
            "unsolicited Kaspa RPC response without an active request".into(),
        )
    })?;
    if decoded.id != Some(active.request_id) {
        let actual = decoded.id.unwrap_or_default();
        let error = NetworkError::MismatchedRequestId {
            expected: active.request_id,
            actual,
        };
        let _ = active.response.send(Err(error.clone()));
        return Err(error);
    }

    match validate_response(&frame, active.request_id, active.operation) {
        Ok(payload) => {
            if active.operation == Operation::Subscribe
                && !subscriptions.iter().any(|item| item == &active.payload)
            {
                subscriptions.push(active.payload.clone());
            }
            let _ = active.response.send(Ok(payload));
        }
        Err(error) => {
            let _ = active.response.send(Err(error));
        }
    }
    Ok(())
}

async fn establish_stream(
    endpoint: &str,
    timeout: Duration,
    max_retries: u8,
    subscriptions: &[Vec<u8>],
    notifications: &mut Notifications,
) -> Result<NativeStream, NetworkError> {
    let mut stream = connect_stream(endpoint, timeout, max_retries).await?;
    for payload in subscriptions {
        replay_subscription(&mut stream, timeout, payload, notifications).await?;
    }
    Ok(stream)
}

async fn replay_subscription(
    stream: &mut NativeStream,
    timeout: Duration,
    payload: &[u8],
    notifications: &mut Notifications,
) -> Result<(), NetworkError> {
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let bytes = request::encode(&WrpcRequest {
        id: request_id,
        operation: Operation::Subscribe,
        payload,
    })?;
    stream
        .send(Message::Binary(bytes.into()))
        .await
        .map_err(|_| NetworkError::SendFailed)?;
    loop {
        let frame = match tokio::time::timeout(timeout, receive_binary(stream)).await {
            Ok(result) => result?,
            Err(_) => return Err(NetworkError::ResponseTimeout),
        };
        let decoded = response::decode(&frame)?;
        if decoded.id.is_some() {
            validate_response(&frame, request_id, Operation::Subscribe)?;
            return Ok(());
        }
        if decoded.kind != ResponseKind::Notification {
            return Err(NetworkError::UnexpectedResponse(
                "Kaspa server message without request id was not a notification".into(),
            ));
        }
        notifications.deliver(frame)?;
    }
}

async fn connect_stream(
    endpoint: &str,
    timeout: Duration,
    max_retries: u8,
) -> Result<NativeStream, NetworkError> {
    let mut retry = 0u8;
    loop {
        let connect =
            connect_async_tls_with_config(endpoint, None, false, Some(super::tls::connector()?));
        let result = tokio::time::timeout(timeout, connect).await;
        match result {
            Ok(Ok((stream, _))) => return Ok(stream),
            Ok(Err(_)) if retry < max_retries => {
                retry = retry.saturating_add(1);
                sleep_connect_backoff(retry).await;
            }
            Err(_) if retry < max_retries => {
                retry = retry.saturating_add(1);
                sleep_connect_backoff(retry).await;
            }
            Ok(Err(error)) => return Err(NetworkError::ConnectionFailed(error.to_string())),
            Err(_) => return Err(NetworkError::ConnectTimeout),
        }
    }
}

fn fail_active_call(active: Option<ActiveCall>, error: &NetworkError) {
    if let Some(active) = active {
        let _ = active.response.send(Err(error.clone()));
    }
}

fn fail_all_queued_calls(queued: &mut VecDeque<QueuedCall>, error: &NetworkError) {
    while let Some(call) = queued.pop_front() {
        let _ = call.response.send(Err(error.clone()));
    }
}

async fn receive_from(stream: Option<&mut NativeStream>) -> Result<Vec<u8>, NetworkError> {
    match stream {
        Some(stream) => receive_binary(stream).await,
        None => pending().await,
    }
}

async fn wait_for_deadline(deadline: Option<Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        pending::<()>().await;
    }
}

#[cfg(test)]
mod tests;
