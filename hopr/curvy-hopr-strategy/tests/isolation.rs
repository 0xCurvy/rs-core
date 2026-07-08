//! Failure-isolation + composition proof, using the **real** hoprnet
//! `hopr_strategy::strategy::{MultiStrategy, Strategy}` with zero modifications.
//!
//! These tests do NOT need the blokli-env stack: they exercise the `MultiStrategy`
//! isolation contract with an out-of-crate, CurvyStrategy-shaped stand-in (a bounded
//! interval loop that swallows its own transient errors) alongside the crate's real
//! [`FaultySibling`] (panic / error). This mirrors hoprnet's own
//! `test_multi_strategy_sub_failure_does_not_propagate` /
//! `test_multi_strategy_accepts_external_strategy`, but with our types.

use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use curvy_hopr_strategy::{FaultySibling, HeartbeatStrategy};
use hopr_strategy::errors::{Result as StrategyResult, StrategyError};
use hopr_strategy::strategy::{MultiStrategy, Strategy};

/// A bounded strategy shaped exactly like `CurvyStrategy::run`: sleep on an interval, do
/// fallible work that it swallows on error, count progress, and stop after `target`
/// iterations. Stands in for CurvyStrategy so the isolation test needs no live chain.
struct CountingStrategy {
    target: usize,
    done: Arc<AtomicUsize>,
    /// Iterations on which the internal "work" errors (swallowed — must not abort us).
    err_on: Vec<usize>,
}

impl Display for CountingStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "counting")
    }
}

#[async_trait]
impl Strategy for CountingStrategy {
    async fn run(&mut self) -> StrategyResult<()> {
        let mut i = 0usize;
        loop {
            tokio::time::sleep(Duration::from_millis(15)).await;
            i += 1;
            // Simulate a transient internal failure. Like CurvyStrategy, we swallow it
            // and keep going rather than returning Err.
            let _swallowed: StrategyResult<()> = if self.err_on.contains(&i) {
                Err(StrategyError::Other(anyhow::anyhow!("transient work error on tick {i}")))
            } else {
                Ok(())
            };
            let n = self.done.fetch_add(1, Ordering::SeqCst) + 1;
            if n >= self.target {
                return Ok(());
            }
        }
    }
}

/// A panicking sibling must NOT abort the Curvy-shaped strategy, and `MultiStrategy::run`
/// must still return `Ok`. (tokio catches the panic as a `JoinError`; `MultiStrategy`
/// logs it and drains the rest.)
#[tokio::test]
async fn panicking_sibling_does_not_abort_curvy_shaped_strategy() {
    let done = Arc::new(AtomicUsize::new(0));
    let counting = CountingStrategy { target: 6, done: done.clone(), err_on: vec![] };

    let mut ms = MultiStrategy::new(vec![
        Box::new(FaultySibling::panic_after(Duration::from_millis(10))),
        Box::new(counting),
    ]);

    let res = tokio::time::timeout(Duration::from_secs(10), ms.run())
        .await
        .expect("MultiStrategy hung");
    res.expect("MultiStrategy::run returned Err despite the isolation contract");

    assert_eq!(
        done.load(Ordering::SeqCst),
        6,
        "Curvy-shaped strategy must complete all its work despite a panicking sibling"
    );
}

/// The vice-versa case + an erroring sibling: an erroring sibling does not abort the
/// Curvy-shaped strategy, AND the Curvy-shaped strategy's own swallowed internal errors
/// do not abort its healthy sibling (the heartbeat still beats).
#[tokio::test]
async fn erroring_siblings_are_isolated_both_ways() {
    let done = Arc::new(AtomicUsize::new(0));
    let beats = Arc::new(AtomicUsize::new(0));

    // Curvy-shaped strategy that hits (and swallows) internal errors on ticks 2 and 4.
    let counting = CountingStrategy { target: 6, done: done.clone(), err_on: vec![2, 4] };
    // A healthy heartbeat sibling that must keep beating throughout.
    let heartbeat = HeartbeatStrategy {
        interval: Duration::from_millis(15),
        label: "heartbeat".to_string(),
        beats: Some(beats.clone()),
    };
    // A sibling that returns Err early.
    let err_sibling = FaultySibling::err_after(Duration::from_millis(10));

    let mut ms = MultiStrategy::new(vec![
        Box::new(err_sibling),
        Box::new(counting),
        Box::new(heartbeat),
    ]);

    // The heartbeat runs forever, so bound the whole run with a timeout: by the time it
    // fires, the counting strategy (≈90 ms) has long since finished all 6 iterations.
    let _ = tokio::time::timeout(Duration::from_millis(400), ms.run()).await;

    assert_eq!(
        done.load(Ordering::SeqCst),
        6,
        "Curvy-shaped strategy completed despite an erroring sibling and its own swallowed errors"
    );
    assert!(
        beats.load(Ordering::SeqCst) >= 3,
        "healthy heartbeat sibling kept running (got {} beats)",
        beats.load(Ordering::SeqCst)
    );
}

/// Composition proof: an out-of-crate `impl Strategy` (ours) drops straight into
/// hoprnet's `MultiStrategy` with zero changes to hopr-strategy — the M5 API contract.
#[tokio::test]
async fn out_of_crate_strategies_compose_into_multistrategy() {
    let done = Arc::new(AtomicUsize::new(0));
    let mut ms = MultiStrategy::new(vec![
        Box::new(CountingStrategy { target: 3, done: done.clone(), err_on: vec![] }),
        Box::new(HeartbeatStrategy { interval: Duration::from_millis(15), label: "hb".into(), beats: None }),
    ]);
    assert_eq!(ms.to_string(), "multi_strategy(counting, hb)");
    let _ = tokio::time::timeout(Duration::from_millis(300), ms.run()).await;
    assert_eq!(done.load(Ordering::SeqCst), 3);
}
