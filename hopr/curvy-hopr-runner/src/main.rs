//! curvy-hopr-runner — the M5 live demo.
//!
//! Stands in for the eventual hoprd composition site. It:
//! 1. builds a real [`CurvyClient`] against the live `poc/blokli-env` stack,
//! 2. pre-seeds a committed note to the strategy's own account (shield + commit — the
//!    same path the M2 e2e uses),
//! 3. composes `hopr_strategy::MultiStrategy::new(vec![CurvyStrategy, HeartbeatStrategy,
//!    FaultySibling::panic])` — the REAL hoprnet combinator, unmodified,
//! 4. runs it and waits for the CurvyStrategy loop to detect the seeded balance and
//!    settle a REAL withdrawal tx through blokli — while a sibling deliberately panics,
//!    proving failure isolation.
//!
//! Requires `poc/blokli-env/run.sh up`. Exits non-zero if the demo does not complete.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use curvy_chain_blokli::BlokliSubmitter;
use curvy_chain_rpc::RpcChain;
use curvy_sdk::curvy_core::field::fr_to_dec;
use curvy_sdk::{Account, CurvyClient, Route};

use curvy_hopr_strategy::{
    CurvyStrategy, CurvyStrategyConfig, FaultySibling, HeartbeatStrategy, SettleAction, SettleRecord,
    DEFAULT_SINK,
};
use hopr_strategy::strategy::{MultiStrategy, Strategy};

// anvil dev EOAs (sign + pay gas; NOT Curvy note-owner keys) — same as the M2 e2e.
const ACC0_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // operator (OPERATOR_ROLE)
const ACC0_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ACC1_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"; // relayer / settle submitter

// The Curvy account the strategy watches/settles (distinct from the e2e's Alice/Bob).
const STRAT_SEED: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";

const ETH_TOKEN: u64 = 1;
const GROSS: u128 = 1_000_000_000_000_000_000; // 1 ETH shielded to the strategy account
const THRESHOLD: u128 = 100_000_000_000_000_000; // 0.1 ETH — the seeded net clears this

fn env_urls() -> (String, String) {
    (
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into()),
        std::env::var("BLOKLI_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into()),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,curvy_hopr_strategy=info".into()),
        )
        .init();

    let (rpc_url, blokli_url) = env_urls();
    println!("== Curvy M5 — CurvyStrategy in hopr_strategy::MultiStrategy ==");
    println!("   rpc={rpc_url}  blokli={blokli_url}");

    // ── Build the client against the live stack (mirrors curvy-e2e's wiring) ──────────
    let d = curvy_e2e::deployed_addresses()?;
    let blokli = Arc::new(BlokliSubmitter::new(blokli_url.clone()));
    if !blokli.is_ready().await {
        bail!("bloklid not ready at {blokli_url} — run `poc/blokli-env/run.sh up` first");
    }
    let (network, chain_id) = blokli.chain_info().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    if chain_id != 31337 {
        bail!("unexpected chainId {chain_id} (want 31337)");
    }
    println!("   bloklid ready: network={network} chainId={chain_id}");
    println!("   aggregator={}  portalFactory={}", d.aggregator, d.portal_factory);

    let rpc = Arc::new(
        RpcChain::new(&rpc_url, &d.aggregator, &d.vault, &d.portal_factory)
            .map_err(|e| anyhow::anyhow!("rpc chain: {e}"))?,
    );
    let client = Arc::new(CurvyClient::new(
        blokli.clone(), // TxSubmitter (blokli) — the settle exit path
        rpc.clone(),    // TxSubmitter (direct) — operator/seed path
        rpc.clone(),    // NoteIndexSource
        rpc.clone(),    // RootAnchor
        rpc.clone(),    // FeeConfigSource
        rpc.clone(),    // BalanceReader
        rpc.clone(),    // PortalDirectory
        d.aggregator.clone(),
        d.portal_factory.clone(),
        chain_id,
    ));

    let strat_account = Account::from_raw_private_key(STRAT_SEED)?;
    println!("   strategy account bjjPub = {:?}", strat_account.bjj_pub_dec());

    // ── Pre-seed: shield 1 ETH to the strategy account, then commit it ───────────────
    println!("\n[seed] shield {GROSS} wei to the strategy account, then commitPendingNotes");
    let (seed_note, srows) = client
        .shield(&strat_account, GROSS, ETH_TOKEN, ACC0_KEY, ACC0_ADDR, Route::Direct)
        .await
        .context("seed shield")?;
    println!(
        "   shielded: net note id={}… ({} txs)",
        &fr_to_dec(&seed_note.note_id())[..12.min(fr_to_dec(&seed_note.note_id()).len())],
        srows.len()
    );
    client
        .commit(&[seed_note.note_id()], ACC0_KEY, Route::Direct)
        .await
        .context("seed commit")?;
    let state = client.anchor_state().await?;
    println!("   committed: root advanced, batch {}", state.current_notes_batch_index);

    let dest_before = client.eth_balance(DEFAULT_SINK).await.unwrap_or(0);

    // ── Compose the REAL hopr_strategy::MultiStrategy ────────────────────────────────
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SettleRecord>();

    let curvy = CurvyStrategy::new(
        client.clone(),
        strat_account,
        ACC1_KEY, // EOA that signs + pays gas for the settle
        CurvyStrategyConfig {
            interval: Duration::from_secs(5),
            threshold_wei: THRESHOLD,
            token: ETH_TOKEN,
            action: SettleAction::Withdraw { destination: DEFAULT_SINK.to_string() },
            route: Route::Blokli,
            max_settles: Some(1),
        },
    )
    .with_event_sink(tx);

    let heartbeat = HeartbeatStrategy { interval: Duration::from_secs(2), ..Default::default() };
    // A REAL sibling that panics before the CurvyStrategy settles — proves isolation.
    let faulty = FaultySibling::panic_after(Duration::from_secs(2));

    let mut ms = MultiStrategy::new(vec![
        Box::new(curvy),
        Box::new(heartbeat),
        Box::new(faulty),
    ]);
    println!("\n[compose] {ms}");
    println!("[run] starting MultiStrategy; CurvyStrategy polls every 5s, panic-sibling fires at ~2s\n");

    let ms_task = tokio::spawn(async move {
        // MultiStrategy::run drains all sub-strategies; the panic sibling is isolated.
        let _ = ms.run().await;
    });

    // ── Await the strategy's real settle (or time out) ───────────────────────────────
    let settle = match tokio::time::timeout(Duration::from_secs(180), rx.recv()).await {
        Ok(Some(rec)) => rec,
        Ok(None) => {
            ms_task.abort();
            bail!("strategy event channel closed before any settle");
        }
        Err(_) => {
            ms_task.abort();
            bail!("timed out waiting for the CurvyStrategy to settle");
        }
    };

    // The strategy fired and returned (max_settles=1); its task ends, MultiStrategy
    // drains and returns. Ensure the task is wound down.
    let _ = tokio::time::timeout(Duration::from_secs(5), ms_task).await;

    let dest_after = client.eth_balance(DEFAULT_SINK).await.unwrap_or(0);
    let delta = dest_after.saturating_sub(dest_before);

    println!("\n================ M5 runner ledger ================");
    println!("  strategy detected the seeded note and SETTLED via {}", settle.backend);
    println!("  kind           : {}", settle.kind);
    println!("  note id        : {}", settle.note_id);
    println!("  gross note wei : {}", settle.amount_wei);
    println!("  delivered wei  : {}", settle.delivered_wei);
    println!("  tx hash        : {}", settle.tx_hash);
    println!("  DEST {DEFAULT_SINK} balance delta : {delta} wei");
    println!("  sibling panic isolated : CurvyStrategy settled despite the panicking sibling");
    println!("==================================================");

    if settle.backend != "blokli" {
        bail!("settle did not go through blokli (backend={})", settle.backend);
    }
    if delta != settle.delivered_wei || delta == 0 {
        bail!("DEST balance delta {delta} != delivered {}", settle.delivered_wei);
    }

    println!("\ncurvy-hopr-runner: SETTLE CONFIRMED (real tx via blokli, isolation held)");
    Ok(())
}
