//! blokli-smoke — end-to-end check of the M2 substrate:
//!
//!   1. HTTP  GET /healthz + /readyz on bloklid :8080
//!   2. GraphQL `chainInfo` query (network / chainId / blockNumber)
//!   3. build + sign a trivial ETH transfer from an anvil dev key (alloy, local),
//!      submit the raw pre-signed tx through bloklid's `sendTransactionSync`
//!      GraphQL mutation, assert it returns a mined Transaction, then cross-check
//!      via direct RPC that the receipt exists and succeeded.
//!   4. negative: submit garbage hex and assert a prompt CLEAN error (no hang).
//!
//! This is exactly the TxSubmitter path the Curvy SDK will use in M2+.

use std::time::{Duration, Instant};

use alloy::eips::eip2718::Encodable2718;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{address, Address, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};

// anvil dev account 1 (sender for the smoke transfer — distinct from account 0, the
// Curvy/HOPR deployer, to avoid nonce interference) → account 2.
const ACC1_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const TO_ACC2: Address = address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
const CHAIN_ID: u64 = 31337;

const SYNC_MUTATION: &str = r#"
mutation ($raw: String!, $c: Int) {
  sendTransactionSync(input: { rawTransaction: $raw }, confirmations: $c) {
    __typename
    ... on Transaction { id status transactionHash submittedAt }
    ... on RpcError { code message }
    ... on TimeoutError { code message }
    ... on ContractNotAllowedError { code message }
    ... on FunctionNotAllowedError { code message }
  }
}"#;

const CHAININFO_QUERY: &str = r#"
query {
  chainInfo {
    __typename
    ... on ChainInfo { blockNumber chainId network expectedBlockTime finality }
  }
}"#;

async fn gql(
    client: &reqwest::Client,
    base: &str,
    query: &str,
    variables: serde_json::Value,
) -> Result<serde_json::Value> {
    let resp = client
        .post(format!("{base}/graphql"))
        .json(&serde_json::json!({ "query": query, "variables": variables }))
        .send()
        .await
        .context("graphql POST")?;
    let body: serde_json::Value = resp.json().await.context("graphql decode")?;
    Ok(body)
}

#[tokio::main]
async fn main() -> Result<()> {
    let blokli = std::env::var("BLOKLI_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let rpc = std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut failures = 0u32;

    // ── 1. health / readiness ───────────────────────────────────────────────────
    println!("== [1] bloklid health ==");
    for path in ["healthz", "readyz"] {
        let r = client.get(format!("{blokli}/{path}")).send().await;
        match r {
            Ok(resp) => {
                let code = resp.status();
                let body = resp.text().await.unwrap_or_default();
                println!("  GET /{path} -> {code} {}", body.trim());
                if !code.is_success() {
                    eprintln!("  FAIL: /{path} not healthy");
                    failures += 1;
                }
            }
            Err(e) => {
                eprintln!("  FAIL: GET /{path}: {e}");
                failures += 1;
            }
        }
    }

    // ── 2. chainInfo ────────────────────────────────────────────────────────────
    println!("\n== [2] GraphQL chainInfo ==");
    let ci = gql(&client, &blokli, CHAININFO_QUERY, serde_json::json!({})).await?;
    let ci_node = &ci["data"]["chainInfo"];
    if ci_node["__typename"] == "ChainInfo" {
        println!(
            "  network={} chainId={} blockNumber={} expectedBlockTime={} finality={}",
            ci_node["network"], ci_node["chainId"], ci_node["blockNumber"],
            ci_node["expectedBlockTime"], ci_node["finality"]
        );
        if ci_node["chainId"].as_i64() != Some(CHAIN_ID as i64) {
            eprintln!("  FAIL: unexpected chainId (want {CHAIN_ID})");
            failures += 1;
        }
    } else {
        eprintln!("  FAIL: chainInfo returned {ci}");
        failures += 1;
    }

    // ── 3. positive: raw tx through sendTransactionSync ─────────────────────────
    println!("\n== [3] sendTransactionSync (positive) ==");
    let signer: PrivateKeySigner = ACC1_KEY.parse()?;
    let from = signer.address();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new().connect_http(rpc.parse()?);

    let nonce = provider.get_transaction_count(from).await.context("get nonce")?;
    let gas_price = provider.get_gas_price().await.context("get gas price")?;
    let value = U256::from(1_000_000_000_000_000u128); // 0.001 ETH

    let tx = TransactionRequest::default()
        .with_from(from)
        .with_to(TO_ACC2)
        .with_value(value)
        .with_nonce(nonce)
        .with_chain_id(CHAIN_ID)
        .with_gas_limit(21_000)
        .with_gas_price(gas_price.saturating_mul(2)); // legacy tx (EIP-155)

    let envelope = tx.build(&wallet).await.context("sign tx")?;
    let local_hash: TxHash = *envelope.tx_hash();
    let raw_hex = format!("0x{}", hex::encode(envelope.encoded_2718()));
    println!("  signed {from} -> {TO_ACC2} nonce={nonce} value=0.001ETH");
    println!("  local tx hash = {local_hash}");
    println!("  raw = {}…{} ({} bytes)", &raw_hex[..14.min(raw_hex.len())],
        &raw_hex[raw_hex.len().saturating_sub(6)..], (raw_hex.len() - 2) / 2);

    let t0 = Instant::now();
    let res = gql(
        &client,
        &blokli,
        SYNC_MUTATION,
        serde_json::json!({ "raw": raw_hex, "c": 1 }),
    )
    .await?;
    let elapsed = t0.elapsed();
    let node = &res["data"]["sendTransactionSync"];
    println!("  responded in {elapsed:?}: {node}");
    if res.get("errors").is_some() {
        eprintln!("  FAIL: top-level GraphQL errors: {}", res["errors"]);
        failures += 1;
    }
    let submitted_hash = if node["__typename"] == "Transaction" {
        let h = node["transactionHash"].as_str().unwrap_or_default().to_string();
        println!("  OK: mined via blokli, status={}, hash={h}", node["status"]);
        Some(h)
    } else {
        eprintln!("  FAIL: expected Transaction, got {node}");
        failures += 1;
        None
    };

    // Cross-check via direct RPC that the tx actually landed.
    if let Some(h) = &submitted_hash {
        let hash: TxHash = h.parse().unwrap_or(local_hash);
        match provider.get_transaction_receipt(hash).await? {
            Some(rcpt) => {
                println!(
                    "  RPC cross-check: receipt block={:?} status={} (hash {})",
                    rcpt.block_number, rcpt.status(), rcpt.transaction_hash
                );
                if !rcpt.status() {
                    eprintln!("  FAIL: receipt status = reverted");
                    failures += 1;
                }
                if hash != local_hash {
                    eprintln!("  WARN: blokli hash {hash} != locally computed {local_hash}");
                }
            }
            None => {
                eprintln!("  FAIL: no receipt on-chain for {hash}");
                failures += 1;
            }
        }
    }

    // ── 4. negative: garbage submissions must fail cleanly (no hang) ─────────────
    println!("\n== [4] sendTransactionSync (negative / garbage) ==");
    for (label, raw) in [("garbage-hex", "0xdeadbeef"), ("not-hex", "nothex!!")] {
        let t = Instant::now();
        let res = gql(
            &client,
            &blokli,
            SYNC_MUTATION,
            serde_json::json!({ "raw": raw, "c": 1 }),
        )
        .await?;
        let el = t.elapsed();
        let node = &res["data"]["sendTransactionSync"];
        let typename = node["__typename"].as_str();
        let top_err = res.get("errors").is_some();
        println!("  [{label}] raw={raw:?} -> {el:?}");
        if top_err {
            println!("    clean top-level error: {}", res["errors"][0]["message"]);
        } else {
            println!("    union member: {node}");
        }
        // Clean = we got a definitive error (top-level or a non-Transaction union
        // member), promptly (no hang), and NOT a bogus success.
        let clean = el < Duration::from_secs(20)
            && (top_err || (typename.is_some() && typename != Some("Transaction")));
        if clean {
            println!("    OK: rejected cleanly");
        } else {
            eprintln!("    FAIL: garbage not cleanly rejected (elapsed {el:?}, node {node})");
            failures += 1;
        }
    }

    println!();
    if failures == 0 {
        println!("blokli-smoke: ALL CHECKS PASSED");
        Ok(())
    } else {
        bail!("blokli-smoke: {failures} check(s) FAILED");
    }
}
