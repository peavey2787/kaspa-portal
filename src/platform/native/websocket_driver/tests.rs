use super::*;

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
    let mut notifications = VecDeque::new();
    let mut waiters = VecDeque::new();

    let event = notification(60, &[0xaa]);
    handle_received_frame(
        event.clone(),
        &mut active,
        &mut subscriptions,
        &mut notifications,
        &mut waiters,
    )
    .expect("notification is routed independently");
    assert!(active.is_some());
    assert_eq!(notifications.pop_front(), Some(event));

    handle_received_frame(
        rpc_response(42, Operation::GetBlock, &[0xbb]),
        &mut active,
        &mut subscriptions,
        &mut notifications,
        &mut waiters,
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
    let mut notifications = VecDeque::new();
    let mut waiters = VecDeque::new();

    handle_received_frame(
        rpc_response(77, Operation::Subscribe, &[]),
        &mut active,
        &mut subscriptions,
        &mut notifications,
        &mut waiters,
    )
    .expect("subscription response");

    response_rx
        .try_recv()
        .expect("response channel")
        .expect("subscription success");
    assert_eq!(subscriptions, vec![body]);
}
