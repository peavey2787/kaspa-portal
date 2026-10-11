//! Connecting to the first healthy public node while resolvers still answer.
//!
//! Resolver answers arrive one by one; the first new endpoint is tried at
//! once, and answers keep being collected while that attempt is in flight,
//! so a slow or silent resolver never delays a node that already answered.

use std::collections::VecDeque;
use std::future::Future;

use futures_util::future::{select, Either};
use futures_util::stream::FusedStream;
use futures_util::{Stream, StreamExt};

/// The first endpoint whose connection succeeds, or every failure in order.
pub(crate) async fn first_connected<T, A, C, F>(
    answers: A,
    mut connect: C,
) -> Result<T, Vec<String>>
where
    A: Stream<Item = Result<String, String>> + Unpin,
    C: FnMut(String) -> F,
    F: Future<Output = Result<T, String>>,
{
    let mut race = Race {
        answers: answers.fuse(),
        queued: VecDeque::new(),
        seen: Vec::new(),
        failures: Vec::new(),
    };
    let mut attempt: Option<core::pin::Pin<Box<F>>> = None;
    loop {
        if attempt.is_none() {
            attempt = race
                .queued
                .pop_front()
                .map(|endpoint| Box::pin(connect(endpoint)));
        }
        let outcome = match attempt.as_mut() {
            None if race.answers.is_terminated() => return Err(race.failures),
            None => {
                race.next_answer().await;
                continue;
            }
            // Every resolver has answered: only the attempt is left to wait on.
            Some(pending) if race.answers.is_terminated() => pending.as_mut().await,
            Some(pending) => match select(pending.as_mut(), race.answers.next()).await {
                Either::Left((outcome, _)) => outcome,
                Either::Right((answer, _)) => {
                    race.absorb(answer);
                    continue;
                }
            },
        };
        match outcome {
            Ok(connected) => return Ok(connected),
            Err(error) => race.failures.push(error),
        }
        attempt = None;
    }
}

struct Race<A> {
    answers: futures_util::stream::Fuse<A>,
    queued: VecDeque<String>,
    seen: Vec<String>,
    failures: Vec<String>,
}

impl<A: Stream<Item = Result<String, String>> + Unpin> Race<A> {
    async fn next_answer(&mut self) {
        let answer = self.answers.next().await;
        self.absorb(answer);
    }

    fn absorb(&mut self, answer: Option<Result<String, String>>) {
        match answer {
            None => {}
            Some(Ok(endpoint)) if !self.seen.contains(&endpoint) => {
                self.seen.push(endpoint.clone());
                self.queued.push_back(endpoint);
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => self.failures.push(error),
        }
    }
}
