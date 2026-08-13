use std::{
    fs,
    sync::{Arc, Mutex},
    time::Instant,
};

use curvy_core::{
    field::{Bn254Fr, fr_to_biguint, fr_to_dec},
    hash_utils::sha256_bigint,
    imt::IndexedMerkleTree as RustIndexedMerkleTree,
};
use curvy_prover::CircuitProver as RustCircuitProver;
use napi::{Env, Error, Result, Status, Task, bindgen_prelude::AsyncTask};
use napi_derive::napi;
use rayon::{ThreadPool, ThreadPoolBuilder};

const DEFAULT_PROVER_THREADS: u32 = 1;
const MAX_PROVER_THREADS: u32 = 64;

#[napi(object)]
pub struct CircuitProverOptions {
    pub zkey_path: String,
    pub zkey_sha256: String,
    pub witness_graph_path: String,
    pub witness_graph_sha256: String,
    /// Number of Rayon workers used by this prover. Defaults to one so a
    /// backend cannot accidentally consume every host core.
    pub threads: Option<u32>,
}

#[napi(object)]
pub struct ProofResult {
    pub proof_json: String,
    pub public_signals_json: String,
    pub witness_calculation_ms: f64,
    pub proof_generation_ms: f64,
}

/// Artifact-driven native prover. Circuit identity and dimensions come only
/// from the authenticated witness graph and zkey, so the same API serves every
/// Circom circuit accepted by `curvy-prover`.
#[napi]
pub struct CircuitProver {
    prover: Arc<RustCircuitProver>,
    thread_pool: Arc<ThreadPool>,
    proof_lock: Arc<Mutex<()>>,
    threads: u32,
    artifact_load_ms: f64,
    artifact_initialization_ms: f64,
}

#[napi]
impl CircuitProver {
    #[napi(constructor)]
    pub fn new(options: CircuitProverOptions) -> Result<Self> {
        let threads = options.threads.unwrap_or(DEFAULT_PROVER_THREADS);
        if !(1..=MAX_PROVER_THREADS).contains(&threads) {
            return Err(Error::new(
                Status::InvalidArg,
                format!("threads must be between 1 and {MAX_PROVER_THREADS}; received {threads}"),
            ));
        }
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(threads as usize)
            .thread_name(|index| format!("curvy-prover-{index}"))
            .build()
            .map_err(|error| native_error("create prover thread pool", error))?;

        let load_started = Instant::now();
        let zkey =
            fs::read(&options.zkey_path).map_err(|error| native_error("read zkey", error))?;
        let witness_graph = fs::read(&options.witness_graph_path)
            .map_err(|error| native_error("read witness graph", error))?;
        let artifact_load_ms = elapsed_ms(load_started);

        let initialization_started = Instant::now();
        let prover = RustCircuitProver::from_artifacts(
            &zkey,
            &options.zkey_sha256,
            &witness_graph,
            &options.witness_graph_sha256,
        )
        .map_err(|error| native_error("initialize native prover", error))?;
        let artifact_initialization_ms = elapsed_ms(initialization_started);

        Ok(Self {
            prover: Arc::new(prover),
            thread_pool: Arc::new(thread_pool),
            proof_lock: Arc::new(Mutex::new(())),
            threads,
            artifact_load_ms,
            artifact_initialization_ms,
        })
    }

    #[napi(getter)]
    pub fn artifact_load_ms(&self) -> f64 {
        self.artifact_load_ms
    }

    #[napi(getter)]
    pub fn artifact_initialization_ms(&self) -> f64 {
        self.artifact_initialization_ms
    }

    #[napi(getter)]
    pub fn num_constraints(&self) -> u32 {
        self.prover.num_constraints() as u32
    }

    #[napi(getter)]
    pub fn num_public(&self) -> u32 {
        self.prover.num_public() as u32
    }

    #[napi(getter)]
    pub fn threads(&self) -> u32 {
        self.threads
    }

    #[napi(getter, js_name = "r1csSha256")]
    pub fn r1cs_sha256(&self) -> String {
        self.prover
            .r1cs_sha256()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[napi(ts_return_type = "Promise<ProofResult>")]
    pub fn prove(&self, input_json: String) -> AsyncTask<ProveTask> {
        AsyncTask::new(ProveTask {
            prover: Arc::clone(&self.prover),
            thread_pool: Arc::clone(&self.thread_pool),
            proof_lock: Arc::clone(&self.proof_lock),
            input_json,
        })
    }
}

pub struct ProveTask {
    prover: Arc<RustCircuitProver>,
    thread_pool: Arc<ThreadPool>,
    proof_lock: Arc<Mutex<()>>,
    input_json: String,
}

impl Task for ProveTask {
    type Output = ProofResult;
    type JsValue = ProofResult;

    fn compute(&mut self) -> Result<Self::Output> {
        let _proof_guard = self
            .proof_lock
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "native prover lock poisoned"))?;
        self.thread_pool.install(|| {
            let witness_started = Instant::now();
            let assignment = self
                .prover
                .calculate_witness_json(&self.input_json)
                .map_err(|error| native_error("calculate witness", error))?;
            let witness_calculation_ms = elapsed_ms(witness_started);

            let proof_started = Instant::now();
            let proof = self
                .prover
                .prove_assignment(&assignment)
                .map_err(|error| native_error("generate proof", error))?;
            let proof_generation_ms = elapsed_ms(proof_started);

            Ok(ProofResult {
                proof_json: proof.proof_json,
                public_signals_json: proof.public_signals_json,
                witness_calculation_ms,
                proof_generation_ms,
            })
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi(object)]
pub struct PendingCommitmentInput {
    pub circuit_input_json: String,
    pub input_hash: String,
    pub padded_note_ids: Vec<String>,
    pub new_notes_root: String,
}

/// Native indexed Poseidon tree used by backend services. The tree itself is a
/// core primitive; `build_pending_commitment` is the canonical adapter for the
/// currently deployed pending-notes-commitment circuit input.
#[napi]
pub struct IndexedMerkleTree {
    tree: RustIndexedMerkleTree,
}

#[napi]
impl IndexedMerkleTree {
    #[napi(constructor)]
    pub fn new(depth: u32, leaves_json: String) -> Result<Self> {
        let leaves = parse_fields_json(&leaves_json, "leaves")?;
        let tree = RustIndexedMerkleTree::from_leaves(depth as usize, &leaves)
            .map_err(|error| native_error("initialize native Merkle tree", error))?;
        Ok(Self { tree })
    }

    #[napi]
    pub fn root(&self) -> String {
        fr_to_dec(&self.tree.root())
    }

    #[napi(getter)]
    pub fn leaf_count(&self) -> u32 {
        self.tree.leaf_count() as u32
    }

    /// Advance the tree transactionally: the live tree changes only after all
    /// insertions, sibling proofs, and the circuit input hash succeed.
    #[napi]
    pub fn build_pending_commitment(
        &mut self,
        batch_size: u32,
        pending_note_ids_json: String,
    ) -> Result<PendingCommitmentInput> {
        let pending_note_ids = parse_fields_json(&pending_note_ids_json, "pending note ids")?;
        if pending_note_ids.is_empty() {
            return Err(Error::new(
                Status::InvalidArg,
                "pending note ids must not be empty".to_owned(),
            ));
        }
        if pending_note_ids.len() > batch_size as usize {
            return Err(Error::new(
                Status::InvalidArg,
                format!(
                    "pending note id count {} exceeds batch size {batch_size}",
                    pending_note_ids.len()
                ),
            ));
        }

        let current_notes_root = self.tree.root();
        let current_note_index = self.tree.leaf_count();
        let zero = Bn254Fr::try_from_dec("0")
            .expect("zero is canonical")
            .into_inner();
        let mut padded_note_ids = pending_note_ids;
        padded_note_ids.resize(batch_size as usize, zero);

        let mut work = self.tree.clone();
        let mut siblings = Vec::with_capacity(batch_size as usize);
        for &note_id in &padded_note_ids {
            if note_id == zero {
                siblings.push(vec!["0".to_owned(); self.tree.depth()]);
                continue;
            }
            work.insert(note_id)
                .map_err(|error| native_error("insert pending note", error))?;
            let proof = work
                .create_proof(note_id)
                .map_err(|error| native_error("create pending note proof", error))?;
            siblings.push(proof.siblings.iter().map(fr_to_dec).collect::<Vec<_>>());
        }

        let new_notes_root = work.root();
        let new_note_index = work.leaf_count();
        let mut hash_inputs = padded_note_ids
            .iter()
            .map(fr_to_biguint)
            .collect::<Vec<_>>();
        hash_inputs.push(fr_to_biguint(&current_notes_root));
        hash_inputs.push(fr_to_biguint(&new_notes_root));
        hash_inputs.push(current_note_index.into());
        hash_inputs.push(new_note_index.into());
        let input_hash = sha256_bigint(&hash_inputs).to_str_radix(10);
        let padded_note_ids = padded_note_ids.iter().map(fr_to_dec).collect::<Vec<_>>();
        let current_notes_root = fr_to_dec(&current_notes_root);
        let new_notes_root = fr_to_dec(&new_notes_root);

        let circuit_input_json = serde_json::json!({
            "currentNoteIndex": current_note_index.to_string(),
            "inputHash": input_hash,
            "currentNotesRoot": current_notes_root,
            "pendingNoteIds": padded_note_ids,
            "siblings": siblings,
        })
        .to_string();

        self.tree = work;
        Ok(PendingCommitmentInput {
            circuit_input_json,
            input_hash,
            padded_note_ids,
            new_notes_root,
        })
    }
}

#[napi]
pub fn rs_core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

fn native_error(context: &str, error: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, format!("{context}: {error}"))
}

fn parse_fields_json(json: &str, label: &str) -> Result<Vec<curvy_core::Fr>> {
    let values: Vec<String> = serde_json::from_str(json)
        .map_err(|error| native_error(&format!("parse {label}"), error))?;
    values
        .iter()
        .map(|value| {
            Bn254Fr::try_from_dec(value)
                .map(Bn254Fr::into_inner)
                .map_err(|error| native_error(&format!("parse {label} field element"), error))
        })
        .collect()
}
