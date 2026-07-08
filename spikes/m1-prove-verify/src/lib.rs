//! M1 spike: pure-Rust witness generation + Groth16 prove/verify against Curvy's
//! three **deployed** circuit configs and their on-chain snarkjs verifiers.
//!
//! The verifier registry deployed by v3-e2e's Ignition `Devenv` holds exactly three
//! configs; this spike exercises all of them end-to-end from Rust:
//!
//! | key           | circuit                                       | verifier            | publics |
//! |---------------|-----------------------------------------------|---------------------|---------|
//! | `withdrawal`  | `VerifySingleWithdrawalNoHashing(2,30)`       | `CurvyWithdrawalVerifier`            | `uint256[6]`  |
//! | `aggregation` | `VerifySingleAggregationNoHashing(2,3,30,6)`  | `CurvyAggregationVerifier`           | `uint256[31]` |
//! | `pending`     | `VerifyPendingNotesCommitment(5,30)`          | `CurvyPendingNotesCommitmentVerifier`| `uint256[1]`  |
//!
//! The pipeline (all legs live here so both the `prove-verify` bin and `tests/e2e.rs`
//! drive identical code), per circuit:
//!
//!   1. [`run_offchain`] — circuit input JSON -> **pure-Rust** witness via the iden3
//!      `circom-witnesscalc` evaluation graph -> compare against the snarkjs golden
//!      `.wtns` (by sha256, and byte-for-byte when the golden blob is committed) ->
//!      `curvy-prover` Groth16 proof -> off-chain verify against the zkey's verifying
//!      key -> cross-check public signals vs the snarkjs reference + an independent
//!      recomputation.
//!   2. [`calldata_from_snarkjs`] — snarkjs-shaped proof JSON -> on-chain `verifyProof`
//!      calldata (with the G2 coordinate swap snarkjs applies).
//!   3. [`run_onchain`] — spawn anvil, deploy the deployed verifier bytecode, call
//!      `verifyProof` (expect accept), then corrupted-statement + corrupted-proof
//!      negatives (expect reject). The `uint256[N]` arity differs per circuit; the
//!      three sol! bindings + a dispatch macro generalize the M1 (withdrawal-only) code.
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
/// JS/node/snarkjs, no wasm interpreter. One graph per circuit config; the runtime
/// code path is identical for all three.
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
// Per-circuit configuration + pinned provenance (see README for how these were
// established; all shas re-verified `shasum -a 256`).
// ---------------------------------------------------------------------------

/// One deployed circuit config: fixtures, provenance pins, on-chain arity.
pub struct Circuit {
    /// Short key: `withdrawal` | `aggregation` | `pending`.
    pub key: &'static str,
    /// Human label, e.g. `withdrawal(2,30)`.
    pub label: &'static str,
    /// Fixture subdirectory under `fixtures/` (`""` = flat, for withdrawal/M1).
    pub subdir: &'static str,
    /// Evaluation-graph filename inside the fixture dir.
    pub graph_file: &'static str,
    /// sha256 of the evaluation graph (deterministic `build-circuit` output).
    pub graph_sha256: &'static str,
    /// sha256 of the snarkjs golden `.wtns` == pure-Rust witness.
    pub golden_sha256: &'static str,
    /// Env var overriding the proving-key path.
    pub zkey_env: &'static str,
    /// Default proving-key path (canonical v3-e2e asset; not committed — 13–129 MB).
    pub zkey_default: &'static str,
    /// sha256 of the `_0001.zkey` (identical in zk-keys/v2 and zk-circuits/build/v2 —
    /// same trusted-setup build as the deployed verifier).
    pub zkey_sha256: &'static str,
    /// Number of public signals (== the verifier's `uint256[N]` arity).
    pub num_public: usize,
    /// Deployed-verifier bytecode fixture filename inside the fixture dir.
    pub verifier_bytecode_file: &'static str,
}

impl Circuit {
    pub fn withdrawal() -> Self {
        Circuit {
            key: "withdrawal",
            label: "withdrawal(2,30)",
            subdir: "",
            graph_file: "withdrawal_2_30.graph.bin",
            graph_sha256: "3a7c7a5ad479643cb5b19b024b7b73f1cc32be7eee75d98bbc91e294bf8f6abf",
            golden_sha256: "b57d06927c8ce5afd9ca4100a87f0fe2da7f398ecf47dfe2b54bdad7114d2f28",
            zkey_env: "CURVY_WITHDRAWAL_ZKEY",
            zkey_default: "/Users/vanja/Projects/v3-e2e/packages/zk-keys/v2/withdrawal/verifySingleWithdrawalNoHashing_2_30_0001.zkey",
            zkey_sha256: "c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716",
            num_public: 6,
            verifier_bytecode_file: "CurvyWithdrawalVerifier.bytecode.txt",
        }
    }

    pub fn aggregation() -> Self {
        Circuit {
            key: "aggregation",
            label: "aggregation(2,3,30,6)",
            subdir: "aggregation",
            graph_file: "aggregation_2_3_30.graph.bin",
            graph_sha256: "f757ba006d125ebb25cb3fc900d3c93b1568db59a6f084c48d6127611aab82ce",
            golden_sha256: "5c8156e4ca34ab10a10af6f2e38141c44b9c02aa930f59253e90ee29e3a1d666",
            zkey_env: "CURVY_AGGREGATION_ZKEY",
            zkey_default: "/Users/vanja/Projects/v3-e2e/packages/zk-keys/v2/aggregation/verifySingleAggregationNoHashing_2_3_30_0001.zkey",
            zkey_sha256: "88a85746f60820712199a60ee13241181658250ba9855af61503d306c52ba4e6",
            num_public: 31,
            verifier_bytecode_file: "CurvyAggregationVerifier.bytecode.txt",
        }
    }

    pub fn pending() -> Self {
        Circuit {
            key: "pending",
            label: "pending-notes-commitment(5,30)",
            subdir: "pending",
            graph_file: "pending_5_30.graph.bin",
            graph_sha256: "3cc81fe0a084c0b11bb627c564f20f1f86d5368ffa19d1d558b03c0414b5f69b",
            golden_sha256: "e91726d9f5e9ea2bc3981c32cb490cd5ab5d1eeb2f5a3dc825d7abfdd78729d5",
            zkey_env: "CURVY_PENDING_ZKEY",
            zkey_default: "/Users/vanja/Projects/v3-e2e/packages/zk-keys/v2/pending-notes-commitment/verifyPendingNotesCommitment_5_30_0001.zkey",
            zkey_sha256: "efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847",
            num_public: 1,
            verifier_bytecode_file: "CurvyPendingNotesCommitmentVerifier.bytecode.txt",
        }
    }

    /// All three deployed configs, in deploy order.
    pub fn all() -> Vec<Circuit> {
        vec![Self::withdrawal(), Self::aggregation(), Self::pending()]
    }

    pub fn dir(&self) -> PathBuf {
        if self.subdir.is_empty() {
            fixtures_dir()
        } else {
            fixtures_dir().join(self.subdir)
        }
    }
    pub fn input_path(&self) -> PathBuf {
        self.dir().join("input.json")
    }
    pub fn graph_path(&self) -> PathBuf {
        self.dir().join(self.graph_file)
    }
    pub fn golden_path(&self) -> PathBuf {
        self.dir().join("golden.wtns")
    }
    pub fn expected_public_path(&self) -> PathBuf {
        self.dir().join("expected-public.json")
    }
    pub fn snarkjs_public_path(&self) -> PathBuf {
        self.dir().join("snarkjs-public.json")
    }
    pub fn bytecode_path(&self) -> PathBuf {
        self.dir().join(self.verifier_bytecode_file)
    }
    pub fn zkey_path(&self) -> PathBuf {
        std::env::var(self.zkey_env)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(self.zkey_default))
    }
}

pub fn spike_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
pub fn fixtures_dir() -> PathBuf {
    spike_dir().join("fixtures")
}

/// Back-compat re-exports for the original M1 (withdrawal) pins.
pub const GOLDEN_WTNS_SHA256: &str =
    "b57d06927c8ce5afd9ca4100a87f0fe2da7f398ecf47dfe2b54bdad7114d2f28";
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
    /// evaluation graph sha256 == pinned value (deterministic `build-circuit` output).
    pub graph_matches_pin: bool,
    pub wtns_sha256: String,
    /// pure-Rust witness == committed snarkjs golden `.wtns` (sha256; and byte-for-byte
    /// when the golden blob is present in the fixture dir).
    pub witness_matches_golden: bool,
    pub zkey_sha256: String,
    /// arkworks Groth16 verify against the zkey's verifying key.
    pub offchain_verified: bool,
    pub publics_dec: Vec<String>,
    /// public signals == both `expected-public.json` (independent recomputation) and
    /// the snarkjs `public.json`.
    pub publics_match_reference: bool,
    pub proof_json: String,
    pub public_json: String,
}

pub fn run_offchain(circuit: &Circuit) -> Result<OffchainOutcome> {
    let input = std::fs::read_to_string(circuit.input_path())
        .with_context(|| format!("read {}", circuit.input_path().display()))?;

    // 1) pure-Rust witness generation.
    let graph_bytes = std::fs::read(circuit.graph_path())
        .with_context(|| format!("read graph {}", circuit.graph_path().display()))?;
    let graph_matches_pin = sha256_hex(&graph_bytes) == circuit.graph_sha256;
    let calc = GraphWitnessCalculator::from_graph_bytes(graph_bytes);
    let wtns_bytes = calc.calculate_wtns(&input)?;
    let wtns_sha256 = sha256_hex(&wtns_bytes);
    // Golden comparison: always by sha256 pin; additionally byte-for-byte when the
    // golden `.wtns` blob is committed (withdrawal + aggregation; pending's 7 MB
    // golden is sha-pinned only — see README).
    let sha_matches = wtns_sha256 == circuit.golden_sha256;
    let byte_matches = match std::fs::read(circuit.golden_path()) {
        Ok(golden) => wtns_bytes == golden,
        Err(_) => true, // golden blob absent: rely on the sha pin
    };
    let witness_matches_golden = sha_matches && byte_matches;
    let full_assignment = curvy_prover::wtns::read_wtns(&wtns_bytes);

    // 2) prove (provenance-pinned zkey).
    let zkey = std::fs::read(circuit.zkey_path()).with_context(|| {
        format!(
            "read zkey {} (set {})",
            circuit.zkey_path().display(),
            circuit.zkey_env
        )
    })?;
    let zkey_sha256 = sha256_hex(&zkey);
    if zkey_sha256 != circuit.zkey_sha256 {
        bail!(
            "{}: zkey sha256 mismatch: got {zkey_sha256}, expected {} — wrong artifact",
            circuit.key,
            circuit.zkey_sha256
        );
    }
    let prover = curvy_prover::Prover::from_zkey_bytes(&zkey);
    let proof = prover.prove(&full_assignment);
    let publics = prover.public_inputs(&full_assignment);
    let offchain_verified = prover.verify(&proof, publics);

    // 3) cross-check public signals against the snarkjs reference + expected fixture.
    let public_json = curvy_prover::publics_to_json(publics);
    let publics_dec: Vec<String> = serde_json::from_str(&public_json)?;
    let expected: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(circuit.expected_public_path())
            .with_context(|| format!("read {}", circuit.expected_public_path().display()))?,
    )?;
    let snarkjs_pub: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(circuit.snarkjs_public_path())
            .with_context(|| format!("read {}", circuit.snarkjs_public_path().display()))?,
    )?;
    let publics_match_reference = publics_dec == expected && publics_dec == snarkjs_pub;

    Ok(OffchainOutcome {
        num_constraints: prover.num_constraints(),
        num_public: prover.num_public(),
        full_assignment_len: full_assignment.len(),
        graph_matches_pin,
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

// One binding per deployed verifier — identical shape, different `uint256[N]` arity.
sol! {
    #[sol(rpc)]
    contract CurvyWithdrawalVerifier {
        function verifyProof(uint256[2] _pA, uint256[2][2] _pB, uint256[2] _pC, uint256[6] _pubSignals) external view returns (bool);
    }
}
sol! {
    #[sol(rpc)]
    contract CurvyAggregationVerifier {
        function verifyProof(uint256[2] _pA, uint256[2][2] _pB, uint256[2] _pC, uint256[31] _pubSignals) external view returns (bool);
    }
}
sol! {
    #[sol(rpc)]
    contract CurvyPendingNotesCommitmentVerifier {
        function verifyProof(uint256[2] _pA, uint256[2][2] _pB, uint256[2] _pC, uint256[1] _pubSignals) external view returns (bool);
    }
}

/// On-chain `verifyProof` arguments, in the exact shape the deployed verifier expects
/// (the same transform `snarkjs generatecall` applies). `pubs` length == the circuit's
/// public-signal count (6 / 31 / 1).
#[derive(Clone)]
pub struct OnchainCallData {
    pub p_a: [U256; 2],
    pub p_b: [[U256; 2]; 2],
    pub p_c: [U256; 2],
    pub pubs: Vec<U256>,
}

fn u256_dec(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).map_err(|e| anyhow::anyhow!("parse U256 {s}: {e}"))
}

/// snarkjs-shaped proof JSON + public JSON -> on-chain calldata.
///
/// G1 points (`pi_a`, `pi_c`) pass through unchanged; each G2 coordinate pair of
/// `pi_b` is **swapped** (`[c0,c1] -> [c1,c0]`), matching the Ethereum pairing
/// precompile's coordinate convention that `snarkjs generatecall` encodes. The public
/// signals pass through in witness order (unchanged) — the deployed verifier defines
/// that same order, so no reordering is needed for any arity.
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
    let pubs: Vec<U256> = pubs_v.iter().map(|s| u256_dec(s)).collect::<Result<_>>()?;
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

/// Pack a public-signal slice into the fixed `[U256; N]` the sol! binding wants.
fn to_fixed<const N: usize>(v: &[U256]) -> [U256; N] {
    let mut a = [U256::ZERO; N];
    for (i, x) in v.iter().enumerate().take(N) {
        a[i] = *x;
    }
    a
}

/// Generate a per-verifier async `verifyProof` driver: valid call + corrupted-statement
/// + corrupted-proof negatives, returning `(valid_accepted, stmt_rejected, proof_rejected)`.
/// A tampered proof point may yield `false` **or** a precompile revert (off-curve point)
/// — both count as rejection.
macro_rules! onchain_verifier {
    ($name:ident, $ctr:ident, $n:literal) => {
        async fn $name<P: Provider>(
            provider: &P,
            addr: Address,
            cd: &OnchainCallData,
        ) -> Result<(bool, bool, bool)> {
            let pubs = to_fixed::<$n>(&cd.pubs);
            let verifier = $ctr::new(addr, provider);

            let valid = verifier
                .verifyProof(cd.p_a, cd.p_b, cd.p_c, pubs)
                .call_raw()
                .await
                .map(|o: Bytes| o.last().copied() == Some(1u8));

            let mut bad_pubs = pubs;
            bad_pubs[0] += U256::from(1);
            let bad_stmt = verifier
                .verifyProof(cd.p_a, cd.p_b, cd.p_c, bad_pubs)
                .call_raw()
                .await
                .map(|o: Bytes| o.last().copied() == Some(1u8));

            let mut bad_pc = cd.p_c;
            bad_pc[0] += U256::from(1);
            let bad_proof = verifier
                .verifyProof(cd.p_a, cd.p_b, bad_pc, pubs)
                .call_raw()
                .await
                .map(|o: Bytes| o.last().copied() == Some(1u8));

            Ok((
                matches!(valid, Ok(true)),
                matches!(bad_stmt, Ok(false)),
                !matches!(bad_proof, Ok(true)),
            ))
        }
    };
}

onchain_verifier!(verify_withdrawal, CurvyWithdrawalVerifier, 6);
onchain_verifier!(verify_aggregation, CurvyAggregationVerifier, 31);
onchain_verifier!(verify_pending, CurvyPendingNotesCommitmentVerifier, 1);

pub async fn run_onchain(circuit: &Circuit, cd: &OnchainCallData) -> Result<OnchainOutcome> {
    if cd.pubs.len() != circuit.num_public {
        bail!(
            "{}: expected {} public signals, got {}",
            circuit.key,
            circuit.num_public,
            cd.pubs.len()
        );
    }

    // Spawns anvil (default chain id 31337) and wires a wallet from its dev keys.
    let provider = ProviderBuilder::new().connect_anvil_with_wallet();

    // Deploy the *deployed* verifier bytecode (extracted from the contracts artifact).
    let bc_hex = std::fs::read_to_string(circuit.bytecode_path())
        .with_context(|| format!("read {}", circuit.bytecode_path().display()))?;
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

    let (valid_accepted, corrupted_statement_rejected, corrupted_proof_rejected) =
        match circuit.num_public {
            6 => verify_withdrawal(&provider, verifier_addr, cd).await?,
            31 => verify_aggregation(&provider, verifier_addr, cd).await?,
            1 => verify_pending(&provider, verifier_addr, cd).await?,
            n => bail!("no verifier binding for {n} public signals"),
        };

    Ok(OnchainOutcome {
        verifier_addr,
        valid_accepted,
        corrupted_statement_rejected,
        corrupted_proof_rejected,
    })
}
