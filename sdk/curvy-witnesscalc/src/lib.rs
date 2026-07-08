//! Pure-Rust witness generation + Groth16 proving for Curvy's three deployed circuits
//! (L0.5). This is the M1 spike promoted to a real crate: an iden3
//! `circom-witnesscalc` evaluation graph turns a circuit-input JSON into a
//! snarkjs-identical witness with no JS/node runtime, then `curvy-prover` proves it
//! into a snarkjs-shaped proof the deployed verifiers accept.
//!
//! ## Artifact resolution (documented order)
//! Graphs and proving keys are pinned by sha256 and resolved per circuit:
//! 1. an env-var override (`CURVY_<CIRCUIT>_GRAPH` / `CURVY_<CIRCUIT>_ZKEY`);
//! 2. otherwise a compiled-in default path.
//!
//! Graph defaults point at the **committed** spike fixtures
//! (`spikes/m1-prove-verify/fixtures/**`); the pending graph (13 MB) and every zkey
//! (13/16/129 MB) are gitignored there and resolved from those paths (regenerate with
//! the spike's `run.sh regen-fixtures`). Loading a graph/zkey whose sha256 does not
//! match the pin is a hard error — wrong artifact, wrong trusted setup.

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub mod pending;

/// Circuit input JSON → snarkjs `.wtns` bytes (index 0 is the constant 1). The seam
/// the SDK proves against; the graph impl is the only implementor today.
pub trait WitnessCalculator {
    fn calculate_wtns(&self, input_json: &str) -> Result<Vec<u8>>;
    fn calculate(&self, input_json: &str) -> Result<Vec<Fr>> {
        Ok(curvy_prover::wtns::read_wtns(&self.calculate_wtns(input_json)?))
    }
}

/// The iden3 `circom-witnesscalc` evaluation graph, executed natively in pure Rust.
pub struct GraphWitnessCalculator {
    graph: Vec<u8>,
}

impl GraphWitnessCalculator {
    pub fn from_graph_bytes(graph: Vec<u8>) -> Self {
        Self { graph }
    }
}

impl WitnessCalculator for GraphWitnessCalculator {
    fn calculate_wtns(&self, input_json: &str) -> Result<Vec<u8>> {
        circom_witnesscalc::calc_witness(input_json, &self.graph)
            .map_err(|e| anyhow::anyhow!("circom-witnesscalc: {e:?}"))
    }
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// One deployed circuit config: pinned graph + zkey, on-chain arity. The pins are the
/// spike's re-verified values (see `spikes/m1-prove-verify/README.md`).
pub struct Circuit {
    pub key: &'static str,
    pub label: &'static str,
    graph_env: &'static str,
    graph_default: &'static str,
    graph_sha256: &'static str,
    zkey_env: &'static str,
    zkey_default: &'static str,
    zkey_sha256: &'static str,
    pub num_public: usize,
}

fn spike_fixtures() -> PathBuf {
    // sdk/curvy-witnesscalc → ../../spikes/m1-prove-verify/fixtures
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spikes/m1-prove-verify/fixtures")
}

impl Circuit {
    pub fn withdrawal() -> Self {
        Circuit {
            key: "withdrawal",
            label: "withdrawal(2,30)",
            graph_env: "CURVY_WITHDRAWAL_GRAPH",
            graph_default: "withdrawal_2_30.graph.bin",
            graph_sha256: "3a7c7a5ad479643cb5b19b024b7b73f1cc32be7eee75d98bbc91e294bf8f6abf",
            zkey_env: "CURVY_WITHDRAWAL_ZKEY",
            zkey_default: "/Users/vanja/Projects/v3-e2e/packages/zk-keys/v2/withdrawal/verifySingleWithdrawalNoHashing_2_30_0001.zkey",
            zkey_sha256: "c91d9fdbea6edde296e9676bdb97959f6acb5f32360b5490c01cea9814844716",
            num_public: 6,
        }
    }

    pub fn aggregation() -> Self {
        Circuit {
            key: "aggregation",
            label: "aggregation(2,3,30,6)",
            graph_env: "CURVY_AGGREGATION_GRAPH",
            graph_default: "aggregation/aggregation_2_3_30.graph.bin",
            graph_sha256: "f757ba006d125ebb25cb3fc900d3c93b1568db59a6f084c48d6127611aab82ce",
            zkey_env: "CURVY_AGGREGATION_ZKEY",
            zkey_default: "/Users/vanja/Projects/v3-e2e/packages/zk-keys/v2/aggregation/verifySingleAggregationNoHashing_2_3_30_0001.zkey",
            zkey_sha256: "88a85746f60820712199a60ee13241181658250ba9855af61503d306c52ba4e6",
            num_public: 31,
        }
    }

    pub fn pending() -> Self {
        Circuit {
            key: "pending",
            label: "pending-notes-commitment(5,30)",
            graph_env: "CURVY_PENDING_GRAPH",
            graph_default: "pending/pending_5_30.graph.bin",
            graph_sha256: "3cc81fe0a084c0b11bb627c564f20f1f86d5368ffa19d1d558b03c0414b5f69b",
            zkey_env: "CURVY_PENDING_ZKEY",
            zkey_default: "/Users/vanja/Projects/v3-e2e/packages/zk-keys/v2/pending-notes-commitment/verifyPendingNotesCommitment_5_30_0001.zkey",
            zkey_sha256: "efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847",
            num_public: 1,
        }
    }

    fn graph_path(&self) -> PathBuf {
        std::env::var(self.graph_env)
            .map(PathBuf::from)
            .unwrap_or_else(|_| spike_fixtures().join(self.graph_default))
    }
    fn zkey_path(&self) -> PathBuf {
        std::env::var(self.zkey_env)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(self.zkey_default))
    }

    /// Load + pin-check the evaluation graph.
    pub fn load_calculator(&self) -> Result<GraphWitnessCalculator> {
        let path = self.graph_path();
        let bytes = std::fs::read(&path)
            .with_context(|| format!("{}: read graph {} (set {})", self.key, path.display(), self.graph_env))?;
        let got = sha256_hex(&bytes);
        if got != self.graph_sha256 {
            bail!("{}: graph sha256 mismatch: got {got}, expected {} — wrong/stale artifact", self.key, self.graph_sha256);
        }
        Ok(GraphWitnessCalculator::from_graph_bytes(bytes))
    }

    /// Load + pin-check the proving key into a `curvy-prover::Prover`.
    pub fn load_prover(&self) -> Result<Prover> {
        let path = self.zkey_path();
        let zkey = std::fs::read(&path)
            .with_context(|| format!("{}: read zkey {} (set {})", self.key, path.display(), self.zkey_env))?;
        let got = sha256_hex(&zkey);
        if got != self.zkey_sha256 {
            bail!("{}: zkey sha256 mismatch: got {got}, expected {} — wrong trusted setup", self.key, self.zkey_sha256);
        }
        Ok(Prover {
            inner: curvy_prover::Prover::from_zkey_bytes(&zkey),
            num_public: self.num_public,
        })
    }

    /// End-to-end for this circuit: input JSON → pure-Rust witness → Groth16 proof.
    /// Verifies off-chain before returning (a fast failure localizes to witness/zkey).
    pub fn prove(&self, input_json: &str) -> Result<ProofBundle> {
        let calc = self.load_calculator()?;
        let prover = self.load_prover()?;
        let assignment = calc.calculate(input_json)?;
        prover.prove_assignment(&assignment)
    }
}

/// A pinned prover for one circuit.
pub struct Prover {
    inner: curvy_prover::Prover,
    num_public: usize,
}

/// A snarkjs-shaped proof + its public signals (decimal strings, witness order).
pub struct ProofBundle {
    pub proof_json: String,
    pub public_signals: Vec<String>,
}

impl Prover {
    pub fn prove_assignment(&self, assignment: &[Fr]) -> Result<ProofBundle> {
        let proof = self.inner.prove(assignment);
        let publics = self.inner.public_inputs(assignment);
        if !self.inner.verify(&proof, publics) {
            bail!("off-chain Groth16 verify failed (witness/zkey mismatch)");
        }
        let public_json = curvy_prover::publics_to_json(publics);
        let public_signals: Vec<String> =
            serde_json::from_str(&public_json).context("parse public signals")?;
        if public_signals.len() != self.num_public {
            bail!("expected {} public signals, got {}", self.num_public, public_signals.len());
        }
        Ok(ProofBundle {
            proof_json: curvy_prover::proof_to_snarkjs_json(&proof),
            public_signals,
        })
    }
}
