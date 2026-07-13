//! Strict shield → commit → aggregate through Blokli → scan → withdraw acceptance flow.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use curvy_chain_blokli::BlokliSubmitter;
use curvy_chain_rpc::RpcChain;
use curvy_core::field::{fr_to_biguint, fr_to_dec, Fr};
use curvy_sdk::{Account, CurvyClient, Route};

const ACC0_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ACC0_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ACC1_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const ALICE_SEED: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const BOB_SEED: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";

const ETH_TOKEN: u64 = 1;
const GROSS: u128 = 1_000_000_000_000_000_000; // 1 ETH shielded
const TO_BOB: u128 = 300_000_000_000_000_000; // 0.3 ETH aggregated to Bob

fn fr_u128(x: &Fr) -> u128 {
    use std::convert::TryInto;
    fr_to_biguint(x).try_into().unwrap_or(u128::MAX)
}

fn short(s: &str) -> &str {
    &s[..12.min(s.len())]
}

/// The deployed addresses from `poc/blokli-env/curvy_deployed_addresses.json`.
pub struct Deployed {
    pub aggregator: String,
    pub vault: String,
    pub portal_factory: String,
}

pub fn deployed_addresses() -> Result<Deployed> {
    let path = std::env::var("CURVY_ADDRESSES").unwrap_or_else(|_| {
        format!(
            "{}/../../poc/blokli-env/curvy_deployed_addresses.json",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let raw = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read {path} — run `poc/blokli-env/run.sh image-up` first (deployed-addresses file missing)"
        )
    })?;
    let j: serde_json::Value = serde_json::from_str(&raw).context("parse deployed addresses")?;
    let get = |k: &str| -> Result<String> {
        Ok(j[k]
            .as_str()
            .with_context(|| format!("missing {k}"))?
            .to_string())
    };
    Ok(Deployed {
        aggregator: get("CurvyAggregator#ERC1967Proxy")?,
        vault: get("CurvyVault#ERC1967Proxy")?,
        portal_factory: get("PortalFactory#PortalFactory")?,
    })
}

fn env_urls() -> (String, String) {
    (
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into()),
        std::env::var("BLOKLI_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into()),
    )
}

/// Probes Blokli's readiness endpoint.
pub async fn stack_ready() -> bool {
    let (_, blokli_url) = env_urls();
    BlokliSubmitter::new(blokli_url).is_ready().await
}

struct Ledger {
    rows: Vec<(String, String)>,
}
impl Ledger {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }
    fn pass(&mut self, step: &str, detail: String) {
        println!("  [PASS] {step:<22} {detail}");
        self.rows.push((step.to_string(), detail));
    }
    fn print(&self) {
        println!("\n================ M2 e2e ledger ================");
        for (step, detail) in &self.rows {
            println!("  PASS  {step:<22} {detail}");
        }
        println!("===============================================");
    }
}

/// Runs the full acceptance flow. Any failed step returns an error.
pub async fn run() -> Result<()> {
    let (rpc_url, blokli_url) = env_urls();
    println!("== Curvy M2 e2e — shield → commit → aggregate(blokli) → scan ==");
    println!("   rpc={rpc_url}  blokli={blokli_url}");

    let d = deployed_addresses()?;

    let blokli = Arc::new(BlokliSubmitter::new(blokli_url.clone()));
    if !blokli.is_ready().await {
        bail!("bloklid not ready at {blokli_url} — run `poc/blokli-env/run.sh image-up` first");
    }
    let (network, chain_id) = blokli
        .chain_info()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if chain_id != 31337 {
        bail!("unexpected chainId {chain_id} (want 31337)");
    }
    println!("   bloklid ready: network={network} chainId={chain_id}");
    println!(
        "   aggregator={}\n   vault={}\n   portalFactory={}\n",
        d.aggregator, d.vault, d.portal_factory
    );

    let rpc = Arc::new(
        RpcChain::new(&rpc_url, &d.aggregator, &d.vault, &d.portal_factory)
            .map_err(|e| anyhow::anyhow!("rpc chain: {e}"))?,
    );
    let client = CurvyClient::new(
        blokli.clone(), // TxSubmitter (blokli) — the M2 exit path
        rpc.clone(),    // TxSubmitter (direct) — operator/fallback path
        rpc.clone(),    // NoteIndexSource
        rpc.clone(),    // RootAnchor
        rpc.clone(),    // FeeConfigSource
        rpc.clone(),    // BalanceReader
        rpc.clone(),    // PortalDirectory
        d.aggregator.clone(),
        d.portal_factory.clone(),
        chain_id,
    );

    let alice = Account::from_raw_private_key(ALICE_SEED)?;
    let bob = Account::from_raw_private_key(BOB_SEED)?;
    println!("   alice.bjjPub = {:?}", alice.bjj_pub_dec());
    println!("   bob.bjjPub   = {:?}\n", bob.bjj_pub_dec());

    let mut ledger = Ledger::new();

    println!("[1] shield {GROSS} wei (token {ETH_TOKEN}) to Alice via entry portal");
    let (note_a, rows) = client
        .shield(&alice, GROSS, ETH_TOKEN, ACC0_KEY, ACC0_ADDR, Route::Direct)
        .await
        .context("shield")?;
    ledger.pass(
        "shield",
        format!(
            "net note {} wei id={}… ({} txs via {})",
            fr_u128(&note_a.amount),
            short(&fr_to_dec(&note_a.note_id())),
            rows.len(),
            rows.last().map(|r| r.backend.as_str()).unwrap_or("?"),
        ),
    );

    println!("\n[2] commitPendingNotes([noteA, 0,0,0,0])");
    let rows = client
        .commit(&[note_a.note_id()], ACC0_KEY, Route::Direct)
        .await
        .context("commit")?;
    let state = client.anchor_state().await?;
    let commit_tx = rows
        .last()
        .context("commit returned no transaction result")?;
    ledger.pass(
        "commit",
        format!(
            "root→{}… batch {} via {}",
            short(&state.current_notes_root),
            state.current_notes_batch_index,
            commit_tx.backend
        ),
    );

    println!("\n[3] aggregate: spend noteA → {TO_BOB} to Bob (+change+fee), submit via blokli");
    let (bob_note, rows) = client
        .aggregate(
            &alice,
            &note_a,
            &bob.identity(),
            TO_BOB,
            ACC1_KEY,
            Route::Blokli,
        )
        .await
        .context("aggregate")?;
    let aggregate_tx = rows
        .last()
        .context("aggregation returned no transaction result")?;
    ledger.pass(
        "aggregate-via-blokli",
        format!(
            "Bob note id={}… PENDING, tx {} via {}",
            short(&fr_to_dec(&bob_note.note_id())),
            short(&aggregate_tx.tx_hash),
            aggregate_tx.backend
        ),
    );

    println!("\n[4] Bob scans PendingNotes (ECDH discovery + decrypt + integrity gate)");
    let discovered = client.scan(&bob).await.context("scan")?;
    let want = fr_to_dec(&bob_note.note_id());
    let hit = discovered
        .iter()
        .find(|dsc| fr_to_dec(&dsc.note_id) == want)
        .context("Bob did not discover his aggregation output note")?;
    let amount = fr_u128(&hit.amount);
    let token = fr_to_dec(&hit.token);
    if amount != TO_BOB || token != ETH_TOKEN.to_string() {
        bail!("scan: discovered wrong value amount={amount} token={token} (want {TO_BOB}/{ETH_TOKEN})");
    }
    ledger.pass(
        "scan-discovery",
        format!("Bob discovered {amount} wei token {token} (decrypted, integrity-gated)"),
    );

    const DEST: &str = "0x000000000000000000000000000000000000bEEF";
    println!("\n[5] commit Bob's note, then withdraw to {DEST}");
    let before: u128 = client.eth_balance(DEST).await?;
    client
        .commit(&[bob_note.note_id()], ACC0_KEY, Route::Direct)
        .await
        .context("commit Bob note")?;
    let (delivered, wrows) = client
        .withdraw(&bob, &bob_note, DEST, ACC1_KEY, Route::Blokli)
        .await
        .context("withdraw Bob note through Blokli")?;
    let after: u128 = client.eth_balance(DEST).await?;
    let delta = after.saturating_sub(before);
    if delta != delivered || delivered == 0 {
        bail!("withdrawal balance delta {delta} does not match delivered amount {delivered}");
    }
    let withdrawal_backend = wrows
        .last()
        .context("withdrawal returned no transaction result")?;
    ledger.pass(
        "withdrawal-via-blokli",
        format!(
            "EOA +{delivered} wei (net of fee+gas), via {}",
            withdrawal_backend.backend
        ),
    );

    ledger.print();
    Ok(())
}
