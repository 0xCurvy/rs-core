//! blokli [`TxSubmitter`] adapter — a small reqwest GraphQL client against bloklid
//! (`:8080 /graphql`), porting `poc/blokli-env/rs blokli-smoke`'s submit path into a
//! trait impl. `sendTransactionSync(confirmations: 1)` is the submit path
//! (anvil-localhost finality == 1); the union result is decoded into typed
//! [`ChainError`]s (RpcError / validator rejections / timeouts) so the SDK sees one
//! error model. The caller signs locally and pays gas; blokli never signs.

use async_trait::async_trait;
use curvy_chain_api::{ChainError, Result, TxSubmitter};
use curvy_types::{RawTx, TxOutcome};

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
query { chainInfo { __typename ... on ChainInfo { blockNumber chainId network finality } } }"#;

/// A blokli GraphQL submitter. Point it at the bloklid base URL (default
/// `http://127.0.0.1:8080`).
pub struct BlokliSubmitter {
    client: reqwest::Client,
    base: String,
    confirmations: i64,
}

impl BlokliSubmitter {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            base: base.into(),
            confirmations: 1,
        }
    }

    async fn gql(&self, query: &str, variables: serde_json::Value) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(format!("{}/graphql", self.base))
            .json(&serde_json::json!({ "query": query, "variables": variables }))
            .send()
            .await
            .map_err(|e| ChainError::Transport(format!("graphql POST: {e}")))?;
        resp.json()
            .await
            .map_err(|e| ChainError::Transport(format!("graphql decode: {e}")))
    }

    /// Readiness probe: `GET /readyz` reports `"status":"ready"`.
    pub async fn is_ready(&self) -> bool {
        match self.client.get(format!("{}/readyz", self.base)).send().await {
            Ok(r) => r.text().await.map(|b| b.contains("\"status\":\"ready\"")).unwrap_or(false),
            Err(_) => false,
        }
    }

    /// `chainInfo` — `(network, chainId)` — used by the e2e readiness ledger.
    pub async fn chain_info(&self) -> Result<(String, u64)> {
        let v = self.gql(CHAININFO_QUERY, serde_json::json!({})).await?;
        let node = &v["data"]["chainInfo"];
        let network = node["network"].as_str().unwrap_or_default().to_string();
        let chain_id = node["chainId"].as_i64().unwrap_or_default() as u64;
        Ok((network, chain_id))
    }
}

#[async_trait]
impl TxSubmitter for BlokliSubmitter {
    async fn submit(&self, raw: &RawTx) -> Result<TxOutcome> {
        let res = self
            .gql(
                SYNC_MUTATION,
                serde_json::json!({ "raw": raw.to_hex(), "c": self.confirmations }),
            )
            .await?;

        if let Some(errors) = res.get("errors") {
            if !errors.is_null() {
                return Err(ChainError::Rejected(format!("top-level GraphQL error: {errors}")));
            }
        }
        let node = &res["data"]["sendTransactionSync"];
        match node["__typename"].as_str() {
            Some("Transaction") => {
                let tx_hash = node["transactionHash"].as_str().unwrap_or_default().to_string();
                // blokli's Transaction.status is a string enum ("CONFIRMED"); anything
                // other than a reverted/failed status counts as success on conf=1.
                let status_str = node["status"].as_str().unwrap_or_default();
                let status = !status_str.eq_ignore_ascii_case("FAILED")
                    && !status_str.eq_ignore_ascii_case("REVERTED");
                Ok(TxOutcome { tx_hash, block_number: None, status })
            }
            Some(other) => {
                let msg = node["message"].as_str().unwrap_or("(no message)");
                let code = node["code"].as_str().unwrap_or("");
                Err(ChainError::Rejected(format!("{other} {code}: {msg}")))
            }
            None => Err(ChainError::Decode(format!("unexpected sendTransactionSync result: {node}"))),
        }
    }

    fn backend(&self) -> &'static str {
        "blokli"
    }
}
