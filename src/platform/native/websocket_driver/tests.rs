use super::*;
use crate::platform::native::websocket::MAX_QUEUED_NOTIFICATIONS;
use tokio::sync::oneshot;

fn rpc_response(request_id: u64, operation: Operation, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(12 + payload.len());
    frame.push(1); // Some(request id)
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.push(0); // Success
    frame.push(1); // Some(operation)
    frame.push(operation.code());
    frame.extend_from_slice(payload);
    frame
}

fn notification(operation: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.push(0); // no request id
    frame.push(0xff); // Notification
    frame.push(1); // Some(operation)
    frame.push(operation);
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn notification_does_not_consume_active_rpc_response() {
    let (response_tx, mut response_rx) = oneshot::channel();
    let mut active = Some(ActiveCall {
        request_id: 42,
        operation: Operation::GetBlock,
        payload: Vec::new(),
        response: response_tx,
        deadline: Instant::now() + Duration::from_secs(1),
    });
    let mut subscriptions = Vec::new();
    let mut notifications = Notifications::default();

    let event = notification(60, &[0xaa]);
    handle_received_frame(
        event.clone(),
        &mut active,
        &mut subscriptions,
        &mut notifications,
    )
    .expect("notification is routed independently");
    assert!(active.is_some());
    assert_eq!(notifications.queued.pop_front(), Some(event));

    handle_received_frame(
        rpc_response(42, Operation::GetBlock, &[0xbb]),
        &mut active,
        &mut subscriptions,
        &mut notifications,
    )
    .expect("matching response is delivered");
    assert!(active.is_none());
    assert_eq!(
        response_rx
            .try_recv()
            .expect("response channel")
            .expect("RPC success"),
        vec![0xbb]
    );
}

#[test]
fn successful_subscription_is_retained_for_replay() {
    let body = vec![1, 2, 3, 4];
    let (response_tx, mut response_rx) = oneshot::channel();
    let mut active = Some(ActiveCall {
        request_id: 77,
        operation: Operation::Subscribe,
        payload: body.clone(),
        response: response_tx,
        deadline: Instant::now() + Duration::from_secs(1),
    });
    let mut subscriptions = Vec::new();
    let mut notifications = Notifications::default();

    handle_received_frame(
        rpc_response(77, Operation::Subscribe, &[]),
        &mut active,
        &mut subscriptions,
        &mut notifications,
    )
    .expect("subscription response");

    response_rx
        .try_recv()
        .expect("response channel")
        .expect("subscription success");
    assert_eq!(subscriptions, vec![body]);
}

#[test]
fn a_waiting_caller_is_answered_from_the_queue_first() {
    let mut notifications = Notifications::default();
    notifications.deliver(vec![1]).expect("queued");
    let (waiter, mut received) = oneshot::channel();
    notifications.wait(waiter);
    assert_eq!(
        received.try_recv().expect("answered").expect("frame"),
        vec![1]
    );
    assert!(!notifications.has_waiters());
}

#[test]
fn queued_notifications_skip_callers_that_stopped_waiting() {
    let mut notifications = Notifications::default();
    notifications.deliver(vec![1]).expect("queued");
    notifications.deliver(vec![2]).expect("queued");
    let (gone, closed) = oneshot::channel();
    drop(closed);
    let (waiter, mut received) = oneshot::channel();
    notifications.waiters.push_back(gone);
    notifications.waiters.push_back(waiter);

    notifications.dispatch_queued();

    assert_eq!(
        received.try_recv().expect("answered").expect("frame"),
        vec![1]
    );
    assert_eq!(notifications.queued, VecDeque::from([vec![2]]));
    assert!(!notifications.has_waiters());
}

#[test]
fn the_notification_queue_is_bounded() {
    let mut notifications = Notifications::default();
    for frame in 0..MAX_QUEUED_NOTIFICATIONS {
        notifications
            .deliver(frame.to_le_bytes().to_vec())
            .expect("within capacity");
    }
    assert!(matches!(
        notifications.deliver(vec![0]),
        Err(NetworkError::UnexpectedResponse(_))
    ));
    assert_eq!(notifications.queued.len(), MAX_QUEUED_NOTIFICATIONS);
}

#[test]
fn failing_waiters_reports_the_error_to_each_one() {
    let mut notifications = Notifications::default();
    let (first, mut first_rx) = oneshot::channel();
    let (second, mut second_rx) = oneshot::channel();
    notifications.wait(first);
    notifications.wait(second);
    notifications.fail_waiters(&NetworkError::SendFailed);
    for received in [&mut first_rx, &mut second_rx] {
        assert!(matches!(
            received.try_recv(),
            Ok(Err(NetworkError::SendFailed))
        ));
    }
    assert!(!notifications.has_waiters());
}
