use std::collections::VecDeque;
use std::future::pending;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures_util::SinkExt;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::network::{
    error::NetworkError,
    wrpc::{
        operation::Operation,
        request::{self, WrpcRequest},
        response::{self, ResponseKind},
    },
};

use super::websocket::{
    sleep_connect_backoff, ActiveCall, DriverCommand, NativeStream, QueuedCall,
    MAX_QUEUED_NOTIFICATIONS, NEXT_REQUEST_ID,
};
use super::websocket_io::{receive_binary, validate_response};

pub(super) async fn run_driver(
    endpoint: String,
    timeout: Duration,
    max_retries: u8,
    mut commands: mpsc::Receiver<DriverCommand>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut stream: Option<NativeStream> = None;
    let mut subscriptions: Vec<Vec<u8>> = Vec::new();
    let mut queued_calls: VecDeque<QueuedCall> = VecDeque::new();
    let mut active_call: Option<ActiveCall> = None;
    let mut queued_notifications: VecDeque<Vec<u8>> = VecDeque::new();
    let mut notification_waiters: VecDeque<oneshot::Sender<Result<Vec<u8>, NetworkError>>> =
        VecDeque::new();

    loop {
        if *shutdown.borrow() {
            break;
        }

        dispatch_queued_notifications(&mut queued_notifications, &mut notification_waiters);

        if should_establish_stream(&stream, &queued_calls, &notification_waiters) {
            match establish_stream(
                &endpoint,
                timeout,
                max_retries,
                &subscriptions,
                &mut queued_notifications,
                &mut notification_waiters,
            )
            .await
            {
                Ok(connected) => stream = Some(connected),
                Err(error) => {
                    fail_all_queued_calls(&mut queued_calls, &error);
                    fail_all_notification_waiters(&mut notification_waiters, &error);
                    continue;
                }
            }
        }

        if let Err(error) =
            start_next_queued_call(&mut stream, &mut queued_calls, &mut active_call, timeout).await
        {
            fail_all_notification_waiters(&mut notification_waiters, &error);
            stream = None;
            continue;
        }

        if stream.is_none() {
            tokio::select! {
                changed = shutdown.changed() => {
                    if shutdown_requested(changed, &shutdown) {
                        break;
                    }
                }
                command = commands.recv() => {
                    match command {
                        Some(command) => handle_command(
                            command,
                            &mut queued_calls,
                            &mut queued_notifications,
                            &mut notification_waiters,
                        ),
                        None => break,
                    }
                }
            }
            continue;
        }

        let deadline = active_call.as_ref().map(|call| call.deadline);
        tokio::select! {
            changed = shutdown.changed() => {
                if shutdown_requested(changed, &shutdown) {
                    break;
                }
            }
            command = commands.recv() => {
                match command {
                    Some(command) => handle_command(
                        command,
                        &mut queued_calls,
                        &mut queued_notifications,
                        &mut notification_waiters,
                    ),
                    None => break,
                }
            }
            frame = receive_binary(stream.as_mut().expect("stream checked above")) => {
                let result = frame.and_then(|frame| {
                    handle_received_frame(
                        frame,
                        &mut active_call,
                        &mut subscriptions,
                        &mut queued_notifications,
                        &mut notification_waiters,
                    )
                });
                if let Err(error) = result {
                    fail_active_call(&mut active_call, &error);
                    fail_all_notification_waiters(&mut notification_waiters, &error);
                    stream = None;
                }
            }
            _ = wait_for_deadline(deadline) => {
                let error = NetworkError::ResponseTimeout;
                fail_active_call(&mut active_call, &error);
                fail_all_notification_waiters(&mut notification_waiters, &error);
                // The timed-out response may still arrive later. Drop the socket so
                // it can never be mis-associated with a subsequent request id.
                stream = None;
            }
        }
    }

    let error = NetworkError::ConnectionFailed("Kaspa wRPC driver stopped".into());
    fail_active_call(&mut active_call, &error);
    fail_all_queued_calls(&mut queued_calls, &error);
    fail_all_notification_waiters(&mut notification_waiters, &error);
}

async fn start_next_queued_call(
    stream: &mut Option<NativeStream>,
    queued_calls: &mut VecDeque<QueuedCall>,
    active_call: &mut Option<ActiveCall>,
    timeout: Duration,
) -> Result<(), NetworkError> {
    if !should_start_call(stream, active_call) {
        return Ok(());
    }
    let Some(call) = queued_calls.pop_front() else {
        return Ok(());
    };
    *active_call = Some(
        start_call(
            stream.as_mut().expect("stream checked above"),
            call,
            timeout,
        )
        .await?,
    );
    Ok(())
}

fn shutdown_requested(
    changed: Result<(), tokio::sync::watch::error::RecvError>,
    shutdown: &watch::Receiver<bool>,
) -> bool {
    changed.is_err() || *shutdown.borrow()
}

fn should_establish_stream(
    stream: &Option<NativeStream>,
    queued_calls: &VecDeque<QueuedCall>,
    notification_waiters: &VecDeque<oneshot::Sender<Result<Vec<u8>, NetworkError>>>,
) -> bool {
    stream.is_none() && (!queued_calls.is_empty() || !notification_waiters.is_empty())
}

fn should_start_call(stream: &Option<NativeStream>, active_call: &Option<ActiveCall>) -> bool {
    active_call.is_none() && stream.is_some()
}

async fn start_call(
    stream: &mut NativeStream,
    call: QueuedCall,
    timeout: Duration,
) -> Result<ActiveCall, NetworkError> {
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let bytes = request::encode(&WrpcRequest {
        id: request_id,
        operation: call.operation,
        payload: &call.payload,
    })?;
    if stream.send(Message::Binary(bytes.into())).await.is_err() {
        let error = NetworkError::SendFailed;
        let _ = call.response.send(Err(error.clone()));
        return Err(error);
    }
    Ok(ActiveCall {
        request_id,
        operation: call.operation,
        payload: call.payload,
        response: call.response,
        deadline: Instant::now() + timeout,
    })
}

fn handle_received_frame(
    frame: Vec<u8>,
    active_call: &mut Option<ActiveCall>,
    subscriptions: &mut Vec<Vec<u8>>,
    queued_notifications: &mut VecDeque<Vec<u8>>,
    notification_waiters: &mut VecDeque<oneshot::Sender<Result<Vec<u8>, NetworkError>>>,
) -> Result<(), NetworkError> {
    let decoded = response::decode(&frame)?;
    if decoded.id.is_none() {
        if decoded.kind != ResponseKind::Notification {
            return Err(NetworkError::UnexpectedResponse(
                "Kaspa server frame without request id was not marked as a notification".into(),
            ));
        }
        return queue_or_deliver_notification(frame, queued_notifications, notification_waiters);
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

fn handle_command(
    command: DriverCommand,
    queued_calls: &mut VecDeque<QueuedCall>,
    queued_notifications: &mut VecDeque<Vec<u8>>,
    notification_waiters: &mut VecDeque<oneshot::Sender<Result<Vec<u8>, NetworkError>>>,
) {
    match command {
        DriverCommand::Call {
            operation,
            payload,
            response,
        } => queued_calls.push_back(QueuedCall {
            operation,
            payload,
            response,
        }),
        DriverCommand::NextNotification { response } => {
            if let Some(frame) = queued_notifications.pop_front() {
                let _ = response.send(Ok(frame));
            } else {
                notification_waiters.push_back(response);
            }
        }
    }
}

async fn establish_stream(
    endpoint: &str,
    timeout: Duration,
    max_retries: u8,
    subscriptions: &[Vec<u8>],
    queued_notifications: &mut VecDeque<Vec<u8>>,
    notification_waiters: &mut VecDeque<oneshot::Sender<Result<Vec<u8>, NetworkError>>>,
) -> Result<NativeStream, NetworkError> {
    let mut stream = connect_stream(endpoint, timeout, max_retries).await?;
    for payload in subscriptions {
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
            let frame = match tokio::time::timeout(timeout, receive_binary(&mut stream)).await {
                Ok(result) => result?,
                Err(_) => return Err(NetworkError::ResponseTimeout),
            };
            let decoded = response::decode(&frame)?;
            if decoded.id.is_none() {
                if decoded.kind != ResponseKind::Notification {
                    return Err(NetworkError::UnexpectedResponse(
                        "Kaspa server message without request id was not a notification".into(),
                    ));
                }
                queue_or_deliver_notification(frame, queued_notifications, notification_waiters)?;
                continue;
            }
            validate_response(&frame, request_id, Operation::Subscribe)?;
            break;
        }
    }
    Ok(stream)
}

async fn connect_stream(
    endpoint: &str,
    timeout: Duration,
    max_retries: u8,
) -> Result<NativeStream, NetworkError> {
    let mut retry = 0u8;
    loop {
        let result = tokio::time::timeout(timeout, connect_async(endpoint)).await;
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

fn queue_or_deliver_notification(
    frame: Vec<u8>,
    queued_notifications: &mut VecDeque<Vec<u8>>,
    notification_waiters: &mut VecDeque<oneshot::Sender<Result<Vec<u8>, NetworkError>>>,
) -> Result<(), NetworkError> {
    while let Some(waiter) = notification_waiters.pop_front() {
        if waiter.send(Ok(frame.clone())).is_ok() {
            return Ok(());
        }
    }
    if queued_notifications.len() >= MAX_QUEUED_NOTIFICATIONS {
        return Err(NetworkError::UnexpectedResponse(
            "Kaspa notification queue capacity exceeded".into(),
        ));
    }
    queued_notifications.push_back(frame);
    Ok(())
}

fn dispatch_queued_notifications(
    queued_notifications: &mut VecDeque<Vec<u8>>,
    notification_waiters: &mut VecDeque<oneshot::Sender<Result<Vec<u8>, NetworkError>>>,
) {
    while !queued_notifications.is_empty() && !notification_waiters.is_empty() {
        let frame = queued_notifications.pop_front().expect("checked non-empty");
        let mut delivered = false;
        while let Some(waiter) = notification_waiters.pop_front() {
            if waiter.send(Ok(frame.clone())).is_ok() {
                delivered = true;
                break;
            }
        }
        if !delivered {
            queued_notifications.push_front(frame);
            break;
        }
    }
}

fn fail_active_call(active: &mut Option<ActiveCall>, error: &NetworkError) {
    if let Some(active) = active.take() {
        let _ = active.response.send(Err(error.clone()));
    }
}

fn fail_all_queued_calls(queued: &mut VecDeque<QueuedCall>, error: &NetworkError) {
    while let Some(call) = queued.pop_front() {
        let _ = call.response.send(Err(error.clone()));
    }
}

fn fail_all_notification_waiters(
    waiters: &mut VecDeque<oneshot::Sender<Result<Vec<u8>, NetworkError>>>,
    error: &NetworkError,
) {
    while let Some(waiter) = waiters.pop_front() {
        let _ = waiter.send(Err(error.clone()));
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
