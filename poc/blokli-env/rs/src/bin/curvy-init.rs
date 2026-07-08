//! curvy-init — the two MANDATORY Curvy post-deploy calls, ported from
//! v3-e2e/packages/contracts/evm/scripts/devenv.ts to alloy:
//!
//!   1. initPerTokenGasFees  — vault.setPerTokenGasFees(GasFees[], commitmentGasFeeRoot)
//!      where the root is the depth-6 Poseidon (poseidon2 / @zk-kit IMT) tree over a
//!      full 2^6 leaf set with leaf[tokenId] = pendingNoteCommitment.
//!   2. initFeeNotePublicKey — aggregator.setFeeNotePublicKey(x, y) with the dev
//!      BabyJubJub fee-collector key (DEV_FEE_COLLECTOR from @0xcurvy/common).
//!
//! Without these, aggregation/withdrawal proofs revert. After writing, this binary
//! VERIFIES by reading the values back on-chain.
//!
//! Signer = anvil account 0 (the vault/aggregator owner per ignition environment
//! parameters "local".owner = 0xf39Fd6…92266). RPC defaults to the compose anvil.

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::{bail, Context, Result};
use curvy_core::field::{fr_from_dec, fr_to_dec};
use curvy_core::poseidon::poseidon;
use curvy_core::Fr;

// anvil dev account 0 — deployer/owner of the vault + aggregator.
const ACC0_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// Dev fee-collector BabyJubJub key (devenv.ts DEV_FEE_COLLECTOR_BABYJUBJUB = "x.y").
const FEE_PK_X: &str =
    "5509359784107808046541889973707062912186356978136525798140528612444721440004";
const FEE_PK_Y: &str =
    "5125768395023217094469327424244994953312297627197683956739233494456001838760";

// Per-token gas-fee placeholders (devenv.ts). 1e17 / 2e17 pendingNoteCommitment for
// tokens 1 & 2; 5e16 portalDeployment + withdrawal legs.
const E17_1: &str = "100000000000000000"; // 0.1 ETH — token 1 pendingNoteCommitment
const E17_2: &str = "200000000000000000"; // 0.2 ETH — token 2 pendingNoteCommitment
const E16_5: &str = "50000000000000000"; //  0.05 ETH — portalDeployment / withdrawal
const GAS_FEE_TREE_DEPTH: usize = 6;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Vault {
        struct GasFees {
            uint256 tokenId;
            uint256 portalDeployment;
            uint256 pendingNoteCommitment;
            uint256 withdrawal;
        }
        function setPerTokenGasFees(GasFees[] gasFees, uint256 commitmentGasFeeRoot) external;
        function perTokenGasFees(uint256 tokenId) external view returns (GasFees memory);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Aggregator {
        function setFeeNotePublicKey(uint256 x, uint256 y) external;
        function commitmentFeeRoot() external view returns (uint256);
        function feeNotePublicKey(uint256 index) external view returns (uint256);
        function protocolFeePerThousand() external view returns (uint256);
    }
}

/// depth-6 Poseidon2 merkle root over a full 64-leaf set: leaf[1]=1e17, leaf[2]=2e17,
/// all others 0. Identical to the SDK's `MerkleTree.fromOrderedLeaves({depth:6})`.
fn gas_fee_root() -> U256 {
    let n = 1usize << GAS_FEE_TREE_DEPTH; // 64
    let mut level: Vec<Fr> = vec![fr_from_dec("0"); n];
    level[1] = fr_from_dec(E17_1);
    level[2] = fr_from_dec(E17_2);
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| poseidon(&[pair[0], pair[1]]))
            .collect();
    }
    U256::from_str_radix(&fr_to_dec(&level[0]), 10).expect("root fits in U256")
}

fn u(s: &str) -> U256 {
    U256::from_str_radix(s, 10).expect("decimal U256")
}

fn load_addresses() -> Result<(Address, Address)> {
    let path = std::env::var("CURVY_ADDRESSES")
        .unwrap_or_else(|_| format!("{}/../curvy_deployed_addresses.json", env!("CARGO_MANIFEST_DIR")));
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    let json: serde_json::Value = serde_json::from_str(&raw)?;
    let get = |k: &str| -> Result<Address> {
        json[k]
            .as_str()
            .with_context(|| format!("missing key {k} in {path}"))?
            .parse()
            .map_err(Into::into)
    };
    Ok((get("CurvyVault#ERC1967Proxy")?, get("CurvyAggregator#ERC1967Proxy")?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let rpc = std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let (vault_addr, agg_addr) = load_addresses()?;
    println!("curvy-init: rpc={rpc}");
    println!("  vault      = {vault_addr}");
    println!("  aggregator = {agg_addr}");

    let signer: PrivateKeySigner = ACC0_KEY.parse()?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc.parse()?);

    let vault = Vault::new(vault_addr, &provider);
    let agg = Aggregator::new(agg_addr, &provider);

    // ── 1. initPerTokenGasFees ──────────────────────────────────────────────────
    let root = gas_fee_root();
    println!("\n[1] setPerTokenGasFees — commitmentGasFeeRoot = {root}");
    let gas_fees = vec![
        Vault::GasFees {
            tokenId: U256::from(1),
            portalDeployment: u(E16_5),
            pendingNoteCommitment: u(E17_1),
            withdrawal: u(E16_5),
        },
        Vault::GasFees {
            tokenId: U256::from(2),
            portalDeployment: u(E16_5),
            pendingNoteCommitment: u(E17_2),
            withdrawal: u(E16_5),
        },
    ];
    let r1 = vault
        .setPerTokenGasFees(gas_fees.clone(), root)
        .send()
        .await
        .context("setPerTokenGasFees send")?
        .get_receipt()
        .await
        .context("setPerTokenGasFees receipt")?;
    if !r1.status() {
        bail!("setPerTokenGasFees reverted (tx {})", r1.transaction_hash);
    }
    println!("    mined tx {} (gas {})", r1.transaction_hash, r1.gas_used);

    // ── 2. initFeeNotePublicKey ─────────────────────────────────────────────────
    let (fx, fy) = (u(FEE_PK_X), u(FEE_PK_Y));
    println!("\n[2] setFeeNotePublicKey — x={fx} y={fy}");
    let r2 = agg
        .setFeeNotePublicKey(fx, fy)
        .send()
        .await
        .context("setFeeNotePublicKey send")?
        .get_receipt()
        .await
        .context("setFeeNotePublicKey receipt")?;
    if !r2.status() {
        bail!("setFeeNotePublicKey reverted (tx {})", r2.transaction_hash);
    }
    println!("    mined tx {} (gas {})", r2.transaction_hash, r2.gas_used);

    // ── 3. VERIFY by read-back ──────────────────────────────────────────────────
    println!("\n[3] read-back verification");
    let mut ok = true;

    let onchain_root = agg.commitmentFeeRoot().call().await?;
    let onchain_root = to_u256(onchain_root);
    println!("    aggregator.commitmentFeeRoot() = {onchain_root}");
    if onchain_root != root {
        eprintln!("    MISMATCH: expected root {root}");
        ok = false;
    }

    let px = to_u256(agg.feeNotePublicKey(U256::from(0)).call().await?);
    let py = to_u256(agg.feeNotePublicKey(U256::from(1)).call().await?);
    println!("    aggregator.feeNotePublicKey(0) = {px}");
    println!("    aggregator.feeNotePublicKey(1) = {py}");
    if px != fx || py != fy {
        eprintln!("    MISMATCH: expected fee note pubkey ({fx}, {fy})");
        ok = false;
    }

    let fee_thousand = to_u256(agg.protocolFeePerThousand().call().await?);
    println!("    aggregator.protocolFeePerThousand() = {fee_thousand}");

    for gf in &gas_fees {
        let got = vault.perTokenGasFees(gf.tokenId).call().await?;
        let got = to_gasfees(got);
        println!(
            "    vault.perTokenGasFees({}) = (portal {}, commit {}, withdraw {})",
            gf.tokenId, got.portalDeployment, got.pendingNoteCommitment, got.withdrawal
        );
        if got.portalDeployment != gf.portalDeployment
            || got.pendingNoteCommitment != gf.pendingNoteCommitment
            || got.withdrawal != gf.withdrawal
        {
            eprintln!("    MISMATCH on token {}", gf.tokenId);
            ok = false;
        }
    }

    if ok {
        println!("\ncurvy-init: OK — both calls landed and read back correctly.");
        Ok(())
    } else {
        bail!("curvy-init: read-back verification FAILED");
    }
}

// alloy's single-return `.call()` gives the value directly in 1.x; these shims keep
// the call sites tidy and tolerant if a `...Return` wrapper is produced instead.
fn to_u256<T: Into<U256>>(v: T) -> U256 {
    v.into()
}
fn to_gasfees(v: Vault::GasFees) -> Vault::GasFees {
    v
}
