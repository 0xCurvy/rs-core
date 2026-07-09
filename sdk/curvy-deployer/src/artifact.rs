//! Vendored-artifact loader + Solidity library linking.
//!
//! Each `Artifact` embeds a trimmed Hardhat artifact JSON (`{contractName, sourceName,
//! abi, bytecode, linkReferences}`) at COMPILE TIME via `include_str!`, so `v3-e2e` is
//! never read at build or run time (see `../artifacts/README.md`). We only ever pull
//! the **creation** `bytecode` out; the ABI is carried for provenance and is consumed
//! elsewhere through `curvy-abi`'s `sol!` bindings.

use alloy::primitives::{Address, Bytes};
use anyhow::{bail, Context, Result};

/// A vendored Curvy contract artifact.
pub struct Artifact {
    /// Contract name (for error context / logging).
    pub name: &'static str,
    json: &'static str,
}

impl Artifact {
    const fn new(name: &'static str, json: &'static str) -> Self {
        Self { name, json }
    }

    /// The `bytecode` field (creation bytecode) as a hex string WITHOUT the `0x`.
    fn bytecode_hex(&self) -> Result<String> {
        let v: serde_json::Value =
            serde_json::from_str(self.json).with_context(|| format!("parse artifact {}", self.name))?;
        let bc = v["bytecode"]
            .as_str()
            .with_context(|| format!("{}: missing string .bytecode", self.name))?;
        Ok(bc.strip_prefix("0x").unwrap_or(bc).to_string())
    }

    /// Creation bytecode that has NO library dependencies (must already be fully linked).
    /// Errors if an unresolved `__$…$__` placeholder is present.
    pub fn creation_code(&self) -> Result<Bytes> {
        let hex_str = self.bytecode_hex()?;
        if let Some(i) = hex_str.find("__$") {
            bail!(
                "{}: unresolved library placeholder at char {i} — use creation_code_linked",
                self.name
            );
        }
        Ok(Bytes::from(
            hex::decode(&hex_str).with_context(|| format!("{}: bad bytecode hex", self.name))?,
        ))
    }

    /// Creation bytecode with a single library `placeholder` substituted by `lib`'s
    /// address. solc placeholders are `__$<keccak17>$__` (40 chars = the 20 address
    /// bytes); we string-replace it with the 40-hex-char lowercased address, matching
    /// solc's `linkReferences` (for the aggregator: PoseidonT4 at byte 6783, length 20).
    pub fn creation_code_linked(&self, placeholder: &str, lib: Address) -> Result<Bytes> {
        let hex_str = self.bytecode_hex()?;
        let count = hex_str.matches(placeholder).count();
        if count != 1 {
            bail!("{}: expected exactly 1 `{placeholder}`, found {count}", self.name);
        }
        let addr_hex = hex::encode(lib.as_slice()); // 40 lowercase hex chars, no 0x
        let linked = hex_str.replace(placeholder, &addr_hex);
        if linked.contains("__$") {
            bail!("{}: library placeholder(s) still present after linking", self.name);
        }
        Ok(Bytes::from(
            hex::decode(&linked).with_context(|| format!("{}: bad linked bytecode hex", self.name))?,
        ))
    }
}

// ── the vendored set, embedded at compile time ─────────────────────────────────────
pub const POSEIDON_T4: Artifact = Artifact::new("PoseidonT4", include_str!("../artifacts/PoseidonT4.json"));
pub const AGGREGATOR_IMPL: Artifact =
    Artifact::new("CurvyAggregatorAlphaV2", include_str!("../artifacts/CurvyAggregatorAlphaV2.json"));
pub const VAULT_IMPL: Artifact = Artifact::new("CurvyVaultV2", include_str!("../artifacts/CurvyVaultV2.json"));
pub const AGGREGATION_VERIFIER: Artifact =
    Artifact::new("CurvyAggregationVerifier", include_str!("../artifacts/CurvyAggregationVerifier.json"));
pub const PENDING_NOTES_COMMITMENT_VERIFIER: Artifact = Artifact::new(
    "CurvyPendingNotesCommitmentVerifier",
    include_str!("../artifacts/CurvyPendingNotesCommitmentVerifier.json"),
);
pub const WITHDRAWAL_VERIFIER: Artifact =
    Artifact::new("CurvyWithdrawalVerifier", include_str!("../artifacts/CurvyWithdrawalVerifier.json"));
pub const PORTAL_FACTORY: Artifact = Artifact::new("PortalFactory", include_str!("../artifacts/PortalFactory.json"));
pub const ERC1967_PROXY: Artifact = Artifact::new("ERC1967Proxy", include_str!("../artifacts/ERC1967Proxy.json"));
pub const MULTICALL3: Artifact = Artifact::new("Multicall3", include_str!("../artifacts/Multicall3.json"));
pub const ERC20_MOCK: Artifact = Artifact::new("ERC20Mock", include_str!("../artifacts/ERC20Mock.json"));

/// The PoseidonT4 library placeholder in the aggregator creation bytecode
/// (`keccak256("project/src/v2/utils/PoseidonT4.sol:PoseidonT4")[0..17]`, hex).
pub const POSEIDON_T4_PLACEHOLDER: &str = "__$da668b34bdb7a81662c478d887f0e664bc$__";

/// CreateX keyless-deployment pre-signed raw tx (Nick's method), embedded verbatim.
pub const CREATEX_BOOTSTRAP_TX: &str = include_str!("../artifacts/createx_bootstrap_tx.hex");
