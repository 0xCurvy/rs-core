//! M1 spike: pure-Rust witness generation + Groth16 prove/verify against Curvy's
//! real withdrawal(2,30) circuit and its deployed `CurvyWithdrawalVerifier.sol`.
//!
//! The pipeline (all three legs live here so both the `prove-verify` bin and the
//! `tests/e2e.rs` integration test drive the identical code):
//!
//!   1. [`run_offchain`] — circuit input JSON -> **pure-Rust** witness via the iden3
//!      `circom-witnesscalc` evaluation graph -> byte-compare against the snarkjs
//!      golden `.wtns` -> `curvy-prover` Groth16 proof -> off-chain verify against
//!      the zkey's verifying key -> cross-check public signals vs the snarkjs
//!      reference.
//!   2. [`calldata_from_snarkjs`] — turn the snarkjs-shaped proof JSON into the
//!      on-chain `verifyProof` calldata (with the G2 coordinate swap snarkjs applies).
//!   3. [`run_onchain`] — spawn anvil, deploy the *deployed* verifier bytecode, call
//!      `verifyProof` (expect accept), then a corrupted-statement + corrupted-proof
//!      negative test (expect reject).
//!
//! The witness calculator sits behind the [`WitnessCalculator`] trait — the seam the
//! real SDK's `curvy-witnesscalc` (L0.5) crate will expose.

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Witness-calculator seam
// ---------------------------------------------------------------------------

/// Circuit input JSON -> full witness assignment (index 0 is the constant 1).
pub trait WitnessCalculator {
    fn calculate(&self, input_json: &str) -> Result<Vec<Fr>>;
}

/// Path 1 (§3 option 1): iden3 `circom-witnesscalc` evaluation graph, executed
/// natively in pure Rust. The graph artifact is built once, offline, from the
/// circuit *sources* with the vendored `build-circuit` tool (see README); at
/// runtime this crate depends only on the `circom-witnesscalc` library — no
/// JS/node/snarkjs, no wasm interpreter.
pub struct GraphWitnessCalculator {
    graph: Vec<u8>,
}

impl GraphWitnessCalculator {
    pub fn from_graph_bytes(graph: Vec<u8>) -> Self {
        Self { graph }
    }

    pub fn from_graph_file(path: &Path) -> Result<Self> {
        Ok(Self::from_graph_bytes(
            std::fs::read(path).with_context(|| format!("read graph {}", path.display()))?,
        ))
    }

    /// Raw snarkjs `.wtns` bytes — for byte-comparison against the golden fixture.
    pub fn calculate_wtns(&self, input_json: &str) -> Result<Vec<u8>> {
        circom_witnesscalc::calc_witness(input_json, &self.graph)
            .map_err(|e| anyhow::anyhow!("circom-witnesscalc: {e:?}"))
    }
}

impl WitnessCalculator for GraphWitnessCalculator {
    fn calculate(&self, input_json: &str) -> Result<Vec<Fr>> {
        Ok(curvy_prover::wtns::read_wtns(&self.calculate_wtns(input_json)?))
    }
}

// ---------------------------------------------------------------------------
// Paths + pinned provenance hashes (see README for how these were established)
// ---------------------------------------------------------------------------

pub fn spike_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
pub fn fixtures_dir() -> PathBuf {
    spike_dir().join("fixtures")
}

/// The deployed withdrawal(2,30) proving key. Not committed into the spike (13 MB);
/// read from the canonical v3-e2e asset, override with `CURVY_WITHDRAWAL_ZKEY`.
pub const DEFAULT_ZKEY: &str = "/Users/vanja/Projects/v3-e2e/packages/zk-keys/v2/withdrawal/verifySingleWithdrawalNoHashing_2_30_0001.zkey";

pub fn zkey_path() -> PathBuf {
    std::env::var("CURVY_WITHDRAWAL_ZKEY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ZKEY))
}

/// sha256 of the snarkjs golden witness == pure-Rust witness (see README).
pub const GOLDEN_WTNS_SHA256: &str =
    "b57d06927c8ce5afd9ca4100a87f0fe2da7f398ecf47dfe2b54bdad7114d2f28";
/// sha256 of the deployed withdrawal(2,30) `_0001.zkey` (identical in zk-keys/v2
/// and zk-circuits/build/v2 — same trusted-setup build as the deployed verifier).
pub const ZKEY_SHA256: &str =
    "c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716";

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

// ---------------------------------------------------------------------------
// Off-chain leg
// ---------------------------------------------------------------------------

pub struct OffchainOutcome {
    pub num_constraints: usize,
    pub num_public: usize,
    pub full_assignment_len: usize,
    pub wtns_sha256: String,
    /// pure-Rust witness bytes == committed snarkjs golden `.wtns`.
    pub witness_matches_golden: bool,
    pub zkey_sha256: String,
    /// arkworks Groth16 verify against the zkey's verifying key.
    pub offchain_verified: bool,
    pub publics_dec: Vec<String>,
    /// public signals == both `expected-public.json` and the snarkjs `public.json`.
    pub publics_match_reference: bool,
    pub proof_json: String,
    pub public_json: String,
}

pub fn run_offchain() -> Result<OffchainOutcome> {
    let fx = fixtures_dir();
    let input = std::fs::read_to_string(fx.join("input.json")).context("read fixtures/input.json")?;

    // 1) pure-Rust witness generation.
    let calc = GraphWitnessCalculator::from_graph_file(&fx.join("withdrawal_2_30.graph.bin"))?;
    let wtns_bytes = calc.calculate_wtns(&input)?;
    let wtns_sha256 = sha256_hex(&wtns_bytes);
    let golden = std::fs::read(fx.join("golden.wtns")).context("read fixtures/golden.wtns")?;
    let witness_matches_golden = wtns_bytes == golden;
    let full_assignment = curvy_prover::wtns::read_wtns(&wtns_bytes);

    // 2) prove (provenance-pinned zkey).
    let zkey = std::fs::read(zkey_path())
        .with_context(|| format!("read zkey {} (set CURVY_WITHDRAWAL_ZKEY)", zkey_path().display()))?;
    let zkey_sha256 = sha256_hex(&zkey);
    if zkey_sha256 != ZKEY_SHA256 {
        bail!("zkey sha256 mismatch: got {zkey_sha256}, expected {ZKEY_SHA256} — wrong artifact");
    }
    let prover = curvy_prover::Prover::from_zkey_bytes(&zkey);
    let proof = prover.prove(&full_assignment);
    let publics = prover.public_inputs(&full_assignment);
    let offchain_verified = prover.verify(&proof, publics);

    // 3) cross-check public signals against the snarkjs reference + expected fixture.
    let public_json = curvy_prover::publics_to_json(publics);
    let publics_dec: Vec<String> = serde_json::from_str(&public_json)?;
    let expected: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(fx.join("expected-public.json"))?)?;
    let snarkjs_pub: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(fx.join("snarkjs-public.json"))?)?;
    let publics_match_reference = publics_dec == expected && publics_dec == snarkjs_pub;

    Ok(OffchainOutcome {
        num_constraints: prover.num_constraints(),
        num_public: prover.num_public(),
        full_assignment_len: full_assignment.len(),
        wtns_sha256,
        witness_matches_golden,
        zkey_sha256,
        offchain_verified,
        publics_dec,
        publics_match_reference,
        proof_json: curvy_prover::proof_to_snarkjs_json(&proof),
        public_json,
    })
}

// ---------------------------------------------------------------------------
// On-chain leg (alloy)
// ---------------------------------------------------------------------------

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::sol;

sol! {
    #[sol(rpc)]
    contract CurvyWithdrawalVerifier {
        function verifyProof(
            uint256[2] _pA,
            uint256[2][2] _pB,
            uint256[2] _pC,
            uint256[6] _pubSignals
        ) external view returns (bool);
    }
}

/// On-chain `verifyProof` arguments, in the exact shape the deployed verifier
/// expects (the same transform `snarkjs generatecall` applies).
#[derive(Clone)]
pub struct OnchainCallData {
    pub p_a: [U256; 2],
    pub p_b: [[U256; 2]; 2],
    pub p_c: [U256; 2],
    pub pubs: [U256; 6],
}

fn u256_dec(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).map_err(|e| anyhow::anyhow!("parse U256 {s}: {e}"))
}

/// snarkjs-shaped proof JSON + public JSON -> on-chain calldata.
///
/// G1 points (`pi_a`, `pi_c`) pass through unchanged; each G2 coordinate pair of
/// `pi_b` is **swapped** (`[c0,c1] -> [c1,c0]`), matching the Ethereum pairing
/// precompile's coordinate convention that `snarkjs generatecall` encodes.
pub fn calldata_from_snarkjs(proof_json: &str, public_json: &str) -> Result<OnchainCallData> {
    let p: serde_json::Value = serde_json::from_str(proof_json)?;
    let g1 = |v: &serde_json::Value, i: usize| -> Result<U256> {
        u256_dec(v[i].as_str().context("g1 coordinate not a string")?)
    };
    let b = |i: usize, j: usize| -> Result<U256> {
        u256_dec(p["pi_b"][i][j].as_str().context("g2 coordinate not a string")?)
    };
    let p_a = [g1(&p["pi_a"], 0)?, g1(&p["pi_a"], 1)?];
    let p_b = [[b(0, 1)?, b(0, 0)?], [b(1, 1)?, b(1, 0)?]]; // swap each pair
    let p_c = [g1(&p["pi_c"], 0)?, g1(&p["pi_c"], 1)?];

    let pubs_v: Vec<String> = serde_json::from_str(public_json)?;
    if pubs_v.len() != 6 {
        bail!("expected 6 public signals, got {}", pubs_v.len());
    }
    let mut pubs = [U256::ZERO; 6];
    for (i, s) in pubs_v.iter().enumerate() {
        pubs[i] = u256_dec(s)?;
    }
    Ok(OnchainCallData { p_a, p_b, p_c, pubs })
}

pub struct OnchainOutcome {
    pub verifier_addr: Address,
    /// `verifyProof(valid) == true`.
    pub valid_accepted: bool,
    /// corrupted public statement (bumped `pubSignals[0]`) rejected.
    pub corrupted_statement_rejected: bool,
    /// corrupted proof point (bumped `pC.x`) rejected (false or precompile revert).
    pub corrupted_proof_rejected: bool,
}

pub async fn run_onchain(cd: &OnchainCallData) -> Result<OnchainOutcome> {
    // Spawns anvil (default chain id 31337) and wires a wallet from its dev keys.
    let provider = ProviderBuilder::new().connect_anvil_with_wallet();

    // Deploy the *deployed* verifier bytecode (extracted from the contracts artifact).
    let bc_hex = std::fs::read_to_string(fixtures_dir().join("CurvyWithdrawalVerifier.bytecode.txt"))
        .context("read verifier bytecode fixture")?;
    let code: Bytes = hex::decode(bc_hex.trim().trim_start_matches("0x"))
        .context("decode verifier bytecode hex")?
        .into();
    let receipt = provider
        .send_transaction(TransactionRequest::default().with_deploy_code(code))
        .await?
        .get_receipt()
        .await?;
    let verifier_addr = receipt
        .contract_address
        .context("deploy receipt has no contract address")?;
    let verifier = CurvyWithdrawalVerifier::new(verifier_addr, &provider);

    // eth_call verifyProof, decode the ABI bool from the raw 32-byte output; a
    // revert (e.g. an off-curve point) surfaces as `Err`.
    macro_rules! verify_raw {
        ($cd:expr) => {{
            let cd: &OnchainCallData = $cd;
            verifier
                .verifyProof(cd.p_a, cd.p_b, cd.p_c, cd.pubs)
                .call_raw()
                .await
                .map(|out: Bytes| out.last().copied() == Some(1u8))
        }};
    }

    let valid_accepted = verify_raw!(cd)?;

    let mut bad_stmt = cd.clone();
    bad_stmt.pubs[0] += U256::from(1);
    let corrupted_statement_rejected = matches!(verify_raw!(&bad_stmt), Ok(false));

    let mut bad_proof = cd.clone();
    bad_proof.p_c[0] += U256::from(1);
    // A tampered proof point yields either a `false` result or a precompile revert
    // (off-curve point) — both count as rejection.
    let corrupted_proof_rejected = !matches!(verify_raw!(&bad_proof), Ok(true));

    Ok(OnchainOutcome {
        verifier_addr,
        valid_accepted,
        corrupted_statement_rejected,
        corrupted_proof_rejected,
    })
}
