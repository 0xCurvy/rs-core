//! # curvy-hopr-strategy
//!
//! `impl hopr_strategy::Strategy for CurvyStrategy` — a HOPR strategy that drives the
//! M2 [`CurvyClient`] on an internal timer, with **zero changes to hoprnet's
//! `hopr-strategy` crate**. It composes into `hopr_strategy::strategy::MultiStrategy`
//! exactly like hoprnet's own `test_multi_strategy_accepts_external_strategy`.
//!
//! The strategy is a *thin policy shell* around `Arc<CurvyClient>`: it needs none of
//! hopr-api's node traits (channels/tickets), because it talks to its own chain backend
//! (blokli + direct RPC), so its bound is just `Strategy + Send`. That is the seam the
//! plan (§2.2, §4 M5) predicted.
//!
//! ## Policy v0
//!
//! On each interval tick the strategy:
//! 1. `sync()`s the mirrored committed-notes tree,
//! 2. `scan()`s the chain for notes owned by its account (real ECDH stealth discovery +
//!    the integrity gate),
//! 3. sums the *spendable* (committed, matching-token, not-yet-settled) balance, and
//! 4. when that balance crosses a configured `threshold_wei`, triggers a **real settle**
//!    ([`SettleAction`]) submitted through blokli — a genuine on-chain tx.
//!
//! Errors inside a tick are logged and swallowed (the loop keeps polling); the strategy
//! only *returns* when a configured `max_settles` budget is exhausted (otherwise it runs
//! forever, like every HOPR strategy). This mirrors `MultiStrategy`'s own isolation
//! contract: a strategy that keeps running must not abort on a transient chain error.

use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;

use hopr_strategy::errors::{Result as StrategyResult, StrategyError};
use hopr_strategy::strategy::Strategy;

// curvy-core reached via curvy-sdk's re-export (no direct crates/core path-dep).
use curvy_sdk::curvy_core::field::{fr_to_biguint, fr_to_dec, Fr};
use curvy_sdk::{Account, CurvyClient, OwnedNote, Route};

/// Default sink EOA for withdrawals (matches the M2 e2e's `DEST`).
pub const DEFAULT_SINK: &str = "0x000000000000000000000000000000000000bEEF";

/// What the strategy does when the spendable balance crosses the threshold.
#[derive(Clone, Debug)]
pub enum SettleAction {
    /// Withdraw a discovered committed note to a plain EOA (value visibly leaves the
    /// pool). The default, simplest real settle.
    Withdraw {
        /// Destination EOA (hex `0x…`).
        destination: String,
    },
}

impl Default for SettleAction {
    fn default() -> Self {
        SettleAction::Withdraw { destination: DEFAULT_SINK.to_string() }
    }
}

/// Policy configuration for [`CurvyStrategy`]. All fields have sane PoC defaults.
/// (No `Debug` derive: `curvy_sdk::Route` doesn't implement it — the sdk is left as-is.)
#[derive(Clone)]
pub struct CurvyStrategyConfig {
    /// How often the policy loop wakes to sync/scan/settle.
    pub interval: Duration,
    /// Spendable balance (wei) that must be crossed before a settle fires.
    pub threshold_wei: u128,
    /// Token id to watch/settle (PoC: `1` == native/ETH).
    pub token: u64,
    /// What to do when the threshold is crossed.
    pub action: SettleAction,
    /// Which submitter to route the settle through (`Blokli` for the PoC exit path).
    pub route: Route,
    /// Stop after this many settles (`None` = run forever, like a production strategy).
    /// The runner/tests set `Some(1)` so a demo terminates deterministically.
    pub max_settles: Option<usize>,
}

impl Default for CurvyStrategyConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            threshold_wei: 1,
            token: 1,
            action: SettleAction::default(),
            route: Route::Blokli,
            max_settles: None,
        }
    }
}

/// A record of one real settle the strategy performed — surfaced to observers (the
/// runner) via the optional event sink.
#[derive(Clone, Debug)]
pub struct SettleRecord {
    /// The settled note id (decimal).
    pub note_id: String,
    /// Settle kind, e.g. `"withdraw"`.
    pub kind: String,
    /// The note's gross amount (wei).
    pub amount_wei: u128,
    /// Amount actually delivered to the destination (net of on-chain fees/gas).
    pub delivered_wei: u128,
    /// The on-chain transaction hash of the settle.
    pub tx_hash: String,
    /// The submitter backend that carried it (`"blokli"` / `"direct-rpc"`).
    pub backend: String,
}

/// A HOPR [`Strategy`] that settles Curvy notes on a timer via `Arc<CurvyClient>`.
pub struct CurvyStrategy {
    client: Arc<CurvyClient>,
    account: Account,
    /// EOA that signs + pays gas for the settle tx (not a Curvy note key).
    submitter_priv: String,
    config: CurvyStrategyConfig,
    events: Option<UnboundedSender<SettleRecord>>,
    /// Note ids already settled this run (avoid re-spending the same note).
    settled: HashSet<String>,
    label: String,
}

impl CurvyStrategy {
    /// Build a strategy. `submitter_priv` is the EOA hex key that signs and pays gas for
    /// the settle transactions (the Curvy note-owner keys live in `account`).
    pub fn new(
        client: Arc<CurvyClient>,
        account: Account,
        submitter_priv: impl Into<String>,
        config: CurvyStrategyConfig,
    ) -> Self {
        Self {
            client,
            account,
            submitter_priv: submitter_priv.into(),
            config,
            events: None,
            settled: HashSet::new(),
            label: "curvy".to_string(),
        }
    }

    /// Attach an event sink so an observer (the runner) can await settle records.
    pub fn with_event_sink(mut self, tx: UnboundedSender<SettleRecord>) -> Self {
        self.events = Some(tx);
        self
    }

    /// Override the `Display` label (shown in `MultiStrategy`'s name list).
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// One policy iteration. Returns `Ok(Some(record))` when a settle fired, `Ok(None)`
    /// when nothing was spendable yet, `Err` on a (transient) chain/proving failure.
    async fn tick(&mut self) -> anyhow::Result<Option<SettleRecord>> {
        // 1. Reconcile the committed-notes tree. If the root is momentarily behind the
        //    index (fast blocks + finality lag), treat it as "nothing yet" and retry
        //    next tick rather than surfacing an error.
        let leaves = match self.client.sync().await {
            Ok(l) => l,
            Err(e) => {
                tracing::debug!(error = %e, "sync not reconciled yet; will retry next tick");
                return Ok(None);
            }
        };

        // 2. Real stealth discovery of notes owned by our account.
        let discovered = self.client.scan(&self.account).await?;

        // 3. Sum spendable (committed + right token + not already settled) balance and
        //    remember the first spendable note as the settle candidate.
        let want_token = self.config.token.to_string();
        let mut spendable: u128 = 0;
        let mut candidate: Option<OwnedNote> = None;
        for d in &discovered {
            if fr_to_dec(&d.token) != want_token {
                continue;
            }
            // Reconstruct the spendable note. For a SPEND, the witness serializes only
            // `flat()` = [owner.x, owner.y, sharedSecret, amount, token] — ephemeral_key
            // / view_tag are discovery-only and unused, so zeros are fine here.
            let note = OwnedNote {
                owner_pub: self.account.bjj_pub,
                shared_secret: d.shared_secret,
                ephemeral_key: (Fr::from(0u64), Fr::from(0u64)),
                view_tag: 0,
                amount: d.amount,
                token: d.token,
            };
            let nid = fr_to_dec(&note.note_id());
            // Spendable ⇔ present in the committed tree (a shielded-but-uncommitted note
            // cannot be withdrawn) and not already consumed this run.
            if !leaves.iter().any(|l| fr_to_dec(l) == nid) || self.settled.contains(&nid) {
                continue;
            }
            let amt: u128 = fr_to_biguint(&d.amount).try_into().unwrap_or(0);
            spendable = spendable.saturating_add(amt);
            if candidate.is_none() {
                candidate = Some(note);
            }
        }

        tracing::info!(
            spendable_wei = spendable,
            threshold_wei = self.config.threshold_wei,
            discovered = discovered.len(),
            "curvy-strategy tick"
        );

        // 4. Threshold gate.
        if spendable < self.config.threshold_wei || candidate.is_none() {
            return Ok(None);
        }
        let note = candidate.unwrap();
        let nid = fr_to_dec(&note.note_id());

        // 5. Real settle via the configured route.
        match &self.config.action {
            SettleAction::Withdraw { destination } => {
                let (delivered, rows) = self
                    .client
                    .withdraw(&self.account, &note, destination, &self.submitter_priv, self.config.route)
                    .await?;
                self.settled.insert(nid.clone());
                let row = rows.into_iter().next_back();
                let (tx_hash, backend) = row
                    .map(|r| (r.tx_hash, r.backend))
                    .unwrap_or_else(|| ("<none>".into(), "<none>".into()));
                Ok(Some(SettleRecord {
                    note_id: nid,
                    kind: "withdraw".to_string(),
                    amount_wei: fr_to_biguint(&note.amount).try_into().unwrap_or(0),
                    delivered_wei: delivered,
                    tx_hash,
                    backend,
                }))
            }
        }
    }
}

impl Display for CurvyStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

#[async_trait]
impl Strategy for CurvyStrategy {
    async fn run(&mut self) -> StrategyResult<()> {
        tracing::info!(
            interval_s = self.config.interval.as_secs_f64(),
            threshold_wei = self.config.threshold_wei,
            "curvy-strategy started"
        );
        let mut settles = 0usize;
        loop {
            tokio::time::sleep(self.config.interval).await;
            match self.tick().await {
                Ok(Some(rec)) => {
                    settles += 1;
                    tracing::info!(
                        tx = %rec.tx_hash,
                        delivered_wei = rec.delivered_wei,
                        via = %rec.backend,
                        "curvy-strategy settled a real tx"
                    );
                    if let Some(tx) = &self.events {
                        let _ = tx.send(rec);
                    }
                    if let Some(max) = self.config.max_settles {
                        if settles >= max {
                            tracing::info!("curvy-strategy reached max_settles={max}; returning Ok");
                            return Ok(());
                        }
                    }
                }
                Ok(None) => {}
                // Isolation: a transient failure must never abort the strategy (nor,
                // via MultiStrategy, its siblings). Log and keep polling.
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "curvy-strategy tick failed; continuing");
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────
// Companion strategies used by the runner (and handy for tests). All are ordinary
// out-of-crate `impl Strategy` types — further proof the trait composes.
// ─────────────────────────────────────────────────────────────────────────────────────

/// A trivial no-op / heartbeat strategy: wakes on an interval and does nothing but log
/// (and optionally bump a shared counter). Stands in for the other strategies that would
/// share a `MultiStrategy` with Curvy inside a real hoprd.
pub struct HeartbeatStrategy {
    pub interval: Duration,
    pub label: String,
    pub beats: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl Default for HeartbeatStrategy {
    fn default() -> Self {
        Self { interval: Duration::from_secs(3), label: "heartbeat".to_string(), beats: None }
    }
}

impl Display for HeartbeatStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

#[async_trait]
impl Strategy for HeartbeatStrategy {
    async fn run(&mut self) -> StrategyResult<()> {
        loop {
            tokio::time::sleep(self.interval).await;
            if let Some(b) = &self.beats {
                b.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            tracing::debug!("heartbeat");
        }
    }
}

/// How a [`FaultySibling`] misbehaves — used to prove `MultiStrategy` isolation with a
/// REAL sibling in the live runner demo.
#[derive(Clone, Debug)]
pub enum FaultMode {
    /// Panic after the delay (tokio catches it as a `JoinError`; siblings survive).
    PanicAfter(Duration),
    /// Return `Err(..)` after the delay (logged by `MultiStrategy`; siblings survive).
    ErrAfter(Duration),
}

/// A deliberately misbehaving strategy for isolation demonstrations.
pub struct FaultySibling {
    pub mode: FaultMode,
    pub label: String,
}

impl FaultySibling {
    pub fn panic_after(d: Duration) -> Self {
        Self { mode: FaultMode::PanicAfter(d), label: "panic-sibling".to_string() }
    }
    pub fn err_after(d: Duration) -> Self {
        Self { mode: FaultMode::ErrAfter(d), label: "err-sibling".to_string() }
    }
}

impl Display for FaultySibling {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

#[async_trait]
impl Strategy for FaultySibling {
    async fn run(&mut self) -> StrategyResult<()> {
        match self.mode {
            FaultMode::PanicAfter(d) => {
                tokio::time::sleep(d).await;
                panic!("faulty sibling: deliberate panic (isolation test)");
            }
            FaultMode::ErrAfter(d) => {
                tokio::time::sleep(d).await;
                Err(StrategyError::Other(anyhow::anyhow!(
                    "faulty sibling: deliberate error (isolation test)"
                )))
            }
        }
    }
}
