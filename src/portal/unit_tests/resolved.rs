//! The resolved connect tries endpoints as resolvers answer them.

use std::cell::RefCell;
use std::rc::Rc;

use futures::channel::{mpsc, oneshot};
use futures::executor::block_on;
use futures::stream::{self, StreamExt};

use super::super::resolved::first_connected;

fn answers(
    items: &[Result<&str, &str>],
) -> impl futures::Stream<Item = Result<String, String>> + Unpin {
    stream::iter(
        items
            .iter()
            .map(|item| item.map(str::to_owned).map_err(str::to_owned))
            .collect::<Vec<_>>(),
    )
}

#[test]
fn the_first_answered_endpoint_that_connects_wins_and_duplicates_are_tried_once() {
    let tried = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&tried);
    let connected = block_on(first_connected(
        answers(&[
            Err("r1: timeout"),
            Ok("wss://a"),
            Ok("wss://a"),
            Ok("wss://b"),
            Ok("wss://c"),
        ]),
        move |endpoint: String| {
            log.borrow_mut().push(endpoint.clone());
            async move {
                match endpoint.as_str() {
                    "wss://b" => Ok(endpoint),
                    _ => Err(format!("{endpoint}: refused")),
                }
            }
        },
    ));
    assert_eq!(connected, Ok("wss://b".to_string()));
    assert_eq!(*tried.borrow(), ["wss://a", "wss://b"]);
}

#[test]
fn every_resolver_and_node_failure_is_reported_when_nothing_connects() {
    let outcome = block_on(first_connected(
        answers(&[Ok("wss://a"), Err("r2: HTTP 503"), Ok("wss://b")]),
        |endpoint: String| async move { Err::<(), _>(format!("{endpoint}: refused")) },
    ));
    assert_eq!(
        outcome,
        // Failures are reported in the order they happened.
        Err(vec![
            "wss://a: refused".to_string(),
            "r2: HTTP 503".to_string(),
            "wss://b: refused".to_string(),
        ])
    );
    let silent = block_on(first_connected(answers(&[]), |_: String| async { Ok(()) }));
    assert_eq!(silent, Err(Vec::new()));
}

#[test]
fn answers_keep_arriving_while_a_connection_attempt_is_in_flight() {
    let (answer_tx, answer_rx) = mpsc::unbounded();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    answer_tx
        .unbounded_send(Ok("wss://slow".to_string()))
        .unwrap();
    answer_tx
        .unbounded_send(Ok("wss://fast".to_string()))
        .unwrap();
    // The slow attempt only fails once the later answers have been read,
    // which can only happen if the race polls answers alongside it.
    let release = RefCell::new(Some((answer_tx, release_tx)));
    let reader = answer_rx.inspect(move |answer| {
        if answer.as_deref() == Ok("wss://fast") {
            if let Some((sender, release)) = release.borrow_mut().take() {
                drop(sender);
                release.send(()).unwrap();
            }
        }
    });
    let mut release_rx = Some(release_rx);
    let connected = block_on(first_connected(
        Box::pin(reader),
        move |endpoint: String| {
            let gate = release_rx.take();
            async move {
                match gate {
                    Some(gate) => {
                        gate.await.unwrap();
                        Err(format!("{endpoint}: refused"))
                    }
                    None => Ok(endpoint),
                }
            }
        },
    ));
    assert_eq!(connected, Ok("wss://fast".to_string()));
}
