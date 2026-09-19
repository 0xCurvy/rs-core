use std::{fs::File, io::BufReader, sync::Arc, time::Instant};

use curvy_core::{
    field::{Bn254Fr, fr_from_be_32_checked, fr_to_be_32, fr_to_biguint, fr_to_dec},
    hash_utils::sha256_bigint,
    imt::IndexedMerkleTree as RustIndexedMerkleTree,
};
use curvy_prover::{
    Prover, ResidentProver as RustResidentProver,
    artifacts::manifest::ZkeyChunkManifest,
    artifacts::{BoundedReader, read_file_bounded, read_graph_file_bounded},
};
use curvy_witness::{Limits, WitnessGraph, sage::SageGraph};
use napi::{
    Env, Error, JsDeferred, Result, Status, Task,
    bindgen_prelude::{AsyncTask, Buffer, Object},
};
use napi_derive::napi;
use rayon::{ThreadPool, ThreadPoolBuilder};
use zeroize::Zeroizing;

mod queue;
use queue::SerialQueue;

/// Resource ceiling for the pending-commitment adapter (including zero padding).
const MAX_PENDING_BATCH_SIZE: u32 = 4096;
fn validate_batch_size(batch_size: u32) -> Result<()> {
    if !(1..=MAX_PENDING_BATCH_SIZE).contains(&batch_size) {
        return Err(Error::new(
            Status::InvalidArg,
            "batchSize must be between 1 and 4096",
        ));
    }
    Ok(())
}

const DEFAULT_PROVER_THREADS: u32 = 1;
const MAX_PROVER_THREADS: u32 = 64;

#[napi(object)]
pub struct ResidentProverOptions {
    pub zkey_path: String,
    pub zkey_sha256: String,
    pub witness_graph_path: Option<String>,
    pub witness_graph_sha256: String,
    /// Compile SIGNET to SAGE on initialization. Defaults to false.
    pub use_sage: Option<bool>,
    /// An authenticated precompiled SAGE program. Both path and digest are
    /// required; witnessGraphSha256 still pins the original SIGNET source.
    pub sage_program_path: Option<String>,
    pub sage_program_sha256: Option<String>,
    /// Independently pinned chunk manifest for one-pass resident key loading.
    pub zkey_manifest_path: Option<String>,
    pub zkey_manifest_sha256: Option<String>,
    /// Number of Rayon workers used by this prover. Defaults to one so a
    /// backend cannot accidentally consume every host core.
    pub threads: Option<u32>,
    /// Maximum accepted proofs, including the running proof. Defaults to 8;
    /// excess requests reject immediately. Must be between 1 and 64.
    pub max_pending_proofs: Option<u32>,
}

#[napi(object)]
pub struct ProofResult {
    pub proof_json: String,
    pub public_signals_json: String,
    pub witness_calculation_ms: f64,
    pub proof_generation_ms: f64,
}

/// HAWK resident prover. Circuit identity and dimensions come only from the
/// authenticated witness graph and zkey, so the same API serves every Circom
/// circuit accepted by `curvy-prover`.
#[napi]
pub struct ResidentProver {
    prover: Arc<RustResidentProver>,
    thread_pool: Arc<ThreadPool>,
    proof_queue: Arc<SerialQueue<ProofJob>>,
    artifact_load_ms: f64,
    artifact_initialization_ms: f64,
}

#[napi]
impl ResidentProver {
    #[napi(constructor, catch_unwind)]
    pub fn new(options: ResidentProverOptions) -> Result<Self> {
        Self::initialize(options)
    }

    /// Authenticate and parse both artifacts on a native task instead of the
    /// JavaScript event loop. The constructor is available when deliberately
    /// synchronous startup is preferable.
    #[napi(ts_return_type = "Promise<ResidentProver>", catch_unwind)]
    pub fn create(options: ResidentProverOptions) -> AsyncTask<InitializeTask> {
        AsyncTask::new(InitializeTask {
            options: Some(options),
        })
    }

    fn initialize(options: ResidentProverOptions) -> Result<Self> {
        let threads = options.threads.unwrap_or(DEFAULT_PROVER_THREADS);
        if !(1..=MAX_PROVER_THREADS).contains(&threads) {
            return Err(Error::new(
                Status::InvalidArg,
                format!("threads must be between 1 and {MAX_PROVER_THREADS}; received {threads}"),
            ));
        }
        let queue_capacity = options.max_pending_proofs.unwrap_or(8);
        if !(1..=64).contains(&queue_capacity) {
            return Err(Error::new(
                Status::InvalidArg,
                "maxPendingProofs must be between 1 and 64",
            ));
        }
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(threads as usize)
            .thread_name(|index| format!("curvy-resident-prover-{index}"))
            .build()
            .map_err(|error| native_error("create prover thread pool", error))?;

        let load_started = Instant::now();
        let zkey =
            File::open(&options.zkey_path).map_err(|error| native_error("open zkey", error))?;
        if !zkey
            .metadata()
            .map_err(|error| native_error("stat zkey", error))?
            .is_file()
        {
            return Err(Error::new(
                Status::InvalidArg,
                "zkey must be a regular file",
            ));
        }
        let mut zkey = BufReader::new(
            BoundedReader::new(zkey, 4 * 1024 * 1024 * 1024)
                .map_err(|error| native_error("bound zkey", error))?,
        );
        let manifest = match (&options.zkey_manifest_path, &options.zkey_manifest_sha256) {
            (Some(path), Some(pin)) => Some(
                ZkeyChunkManifest::from_bytes(
                    &read_file_bounded(path, 4 * 1024 * 1024)
                        .map_err(|error| native_error("read zkey manifest", error))?,
                    pin,
                    &options.zkey_sha256,
                )
                .map_err(|error| native_error("authenticate zkey manifest", error))?,
            ),
            (None, None) => None,
            _ => {
                return Err(Error::new(
                    Status::InvalidArg,
                    "zkeyManifestPath and zkeyManifestSha256 must be supplied together",
                ));
            }
        };
        let compiled = match (&options.sage_program_path, &options.sage_program_sha256) {
            (Some(path), Some(_)) => Some(
                read_file_bounded(path, Limits::client().sage_program_bytes)
                    .map_err(|error| native_error("read SAGE program", error))?,
            ),
            (None, None) => None,
            _ => {
                return Err(Error::new(
                    Status::InvalidArg,
                    "sageProgramPath and sageProgramSha256 must be supplied together",
                ));
            }
        };
        let witness_graph = if compiled.is_none() {
            let path = options.witness_graph_path.as_ref().ok_or_else(|| {
                Error::new(
                    Status::InvalidArg,
                    "witnessGraphPath is required without a compiled SAGE program",
                )
            })?;
            read_graph_file_bounded(path, Limits::client())
                .map_err(|error| native_error("read witness graph", error))?
        } else {
            Vec::new()
        };
        let artifact_load_ms = elapsed_ms(load_started);

        let initialization_started = Instant::now();
        let prover = thread_pool.install(|| -> Result<RustResidentProver> {
            let prover = match &manifest {
                Some(manifest) => Prover::from_zkey_manifest_reader(&mut zkey, manifest)
                    .map_err(|error| native_error("load manifest-authenticated zkey", error))?,
                None => Prover::from_zkey_reader(&mut zkey, &options.zkey_sha256)
                    .map_err(|error| native_error("load zkey", error))?,
            };
            let resident = if let Some(program) = &compiled {
                RustResidentProver::from_compiled_sage(
                    prover,
                    program,
                    options
                        .sage_program_sha256
                        .as_deref()
                        .expect("validated SAGE digest"),
                    &options.witness_graph_sha256,
                    Limits::client(),
                )
            } else if options.use_sage.unwrap_or(false) {
                let graph = SageGraph::from_bytes(&witness_graph, &options.witness_graph_sha256)
                    .map_err(|error| native_error("compile SAGE graph", error))?;
                RustResidentProver::with_sage(prover, graph)
            } else {
                let graph = WitnessGraph::from_bytes(&witness_graph, &options.witness_graph_sha256)
                    .map_err(|error| native_error("load witness graph", error))?;
                RustResidentProver::with_graph(prover, graph)
            };
            resident.map_err(|error| native_error("initialize native prover", error))
        })?;
        let artifact_initialization_ms = elapsed_ms(initialization_started);

        let thread_pool = Arc::new(thread_pool);
        let proof_queue = SerialQueue::new(
            Arc::clone(&thread_pool),
            queue_capacity as usize,
            ProofJob::run,
        );
        Ok(Self {
            prover: Arc::new(prover),
            thread_pool,
            proof_queue,
            artifact_load_ms,
            artifact_initialization_ms,
        })
    }

    #[napi(getter, catch_unwind)]
    pub fn artifact_load_ms(&self) -> f64 {
        self.artifact_load_ms
    }

    #[napi(getter, catch_unwind)]
    pub fn artifact_initialization_ms(&self) -> f64 {
        self.artifact_initialization_ms
    }

    #[napi(getter, catch_unwind)]
    pub fn num_constraints(&self) -> u32 {
        self.prover.num_constraints() as u32
    }

    #[napi(getter, catch_unwind)]
    pub fn num_public(&self) -> u32 {
        self.prover.num_public() as u32
    }

    #[napi(getter, catch_unwind)]
    pub fn threads(&self) -> u32 {
        self.thread_pool.current_num_threads() as u32
    }

    #[napi(getter, catch_unwind)]
    pub fn mode(&self) -> String {
        self.prover.mode().as_str().to_owned()
    }

    #[napi(getter, catch_unwind)]
    pub fn profile(&self) -> String {
        self.prover.profile().to_owned()
    }

    #[napi(getter, catch_unwind)]
    pub fn witness_backend(&self) -> String {
        self.prover.witness_backend().to_owned()
    }

    /// SHA-256 of the loaded key's verifying key. Compare it against the
    /// deployed verifier before submitting proofs.
    #[napi(getter, js_name = "verifyingKeyDigest", catch_unwind)]
    pub fn verifying_key_digest(&self) -> String {
        self.prover.verifying_key_digest()
    }

    #[napi(getter, js_name = "r1csSha256", catch_unwind)]
    pub fn r1cs_sha256(&self) -> String {
        self.prover
            .r1cs_sha256()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[napi(ts_return_type = "Promise<ProofResult>", catch_unwind)]
    pub fn prove<'env>(&self, env: &'env Env, input_json: String) -> Result<Object<'env>> {
        let input_json = Zeroizing::new(input_json);
        let (deferred, promise) = env.create_deferred::<ProofResult, ProofResolver>()?;
        if input_json.len() > Limits::client().input_json_bytes {
            deferred.reject(Error::new(
                Status::InvalidArg,
                "proof input JSON exceeds 16 MiB",
            ));
            return Ok(promise);
        }
        let job = ProofJob {
            prover: Arc::clone(&self.prover),
            input_json,
            deferred,
        };
        if let Err(job) = self.proof_queue.submit(job) {
            job.deferred.reject(Error::new(
                Status::QueueFull,
                "resident prover queue is full",
            ));
        }
        Ok(promise)
    }
}

pub struct InitializeTask {
    options: Option<ResidentProverOptions>,
}

impl Task for InitializeTask {
    type Output = ResidentProver;
    type JsValue = ResidentProver;

    fn compute(&mut self) -> Result<Self::Output> {
        let options = self
            .options
            .take()
            .expect("N-API initialization task is computed only once");
        ResidentProver::initialize(options)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

type ProofResolver = Box<dyn FnOnce(Env) -> Result<ProofResult> + Send>;

struct ProofJob {
    prover: Arc<RustResidentProver>,
    input_json: Zeroizing<String>,
    deferred: JsDeferred<ProofResult, ProofResolver>,
}

impl ProofJob {
    fn run(self) -> queue::Completion {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let witness_started = Instant::now();
            let assignment = Zeroizing::new(
                self.prover
                    .calculate_witness_json(&self.input_json)
                    .map_err(|error| native_error("calculate witness", error))?,
            );
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
        }))
        .unwrap_or_else(|_| {
            Err(Error::new(
                Status::GenericFailure,
                "proof computation panicked",
            ))
        });
        Box::new(move || match result {
            Ok(output) => self.deferred.resolve(Box::new(move |_| Ok(output))),
            Err(error) => self.deferred.reject(error),
        })
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
    #[napi(constructor, catch_unwind)]
    pub fn new(depth: u32, leaves_json: String) -> Result<Self> {
        let leaves = parse_fields_json(&leaves_json, "leaves")?;
        Self::from_leaves(depth, &leaves)
    }

    /// Construct directly from concatenated canonical 32-byte big-endian
    /// BN254 field elements, avoiding decimal strings and a JSON array.
    #[napi(factory, js_name = "fromPackedLeaves", catch_unwind)]
    pub fn from_packed_leaves(depth: u32, packed_leaves: Buffer) -> Result<Self> {
        let leaves = parse_fields_packed(&packed_leaves, "leaves")?;
        Self::from_leaves(depth, &leaves)
    }

    fn from_leaves(depth: u32, leaves: &[curvy_core::Fr]) -> Result<Self> {
        let tree = RustIndexedMerkleTree::from_leaves(depth as usize, leaves)
            .map_err(|error| native_error("initialize native Merkle tree", error))?;
        Ok(Self { tree })
    }

    #[napi(catch_unwind)]
    pub fn root(&self) -> String {
        fr_to_dec(&self.tree.root())
    }

    /// Return the root as one canonical 32-byte big-endian field element.
    #[napi(js_name = "rootPacked", catch_unwind)]
    pub fn root_packed(&self) -> Buffer {
        fr_to_be_32(&self.tree.root()).to_vec().into()
    }

    #[napi(getter, catch_unwind)]
    pub fn leaf_count(&self) -> u32 {
        self.tree.leaf_count() as u32
    }

    /// Advance the tree transactionally: the live tree changes only after all
    /// insertions, sibling proofs, and the circuit input hash succeed.
    #[napi(catch_unwind)]
    pub fn build_pending_commitment(
        &mut self,
        batch_size: u32,
        pending_note_ids_json: String,
    ) -> Result<PendingCommitmentInput> {
        validate_batch_size(batch_size)?;
        if pending_note_ids_json.len() > batch_size as usize * 82 + 2 {
            return Err(Error::new(
                Status::InvalidArg,
                "pending note ids JSON exceeds the batch byte budget",
            ));
        }
        let pending_note_ids = parse_fields_json(&pending_note_ids_json, "pending note ids")?;
        self.build_pending_commitment_fields(batch_size, pending_note_ids)
    }

    /// Packed counterpart to `buildPendingCommitment`. Each pending note id is
    /// a canonical 32-byte big-endian BN254 field element.
    #[napi(js_name = "buildPendingCommitmentPacked", catch_unwind)]
    pub fn build_pending_commitment_packed(
        &mut self,
        batch_size: u32,
        pending_note_ids: Buffer,
    ) -> Result<PendingCommitmentInput> {
        validate_batch_size(batch_size)?;
        if pending_note_ids.len() > batch_size as usize * 32 {
            return Err(Error::new(
                Status::InvalidArg,
                "pending note ids exceed batch size",
            ));
        }
        let pending_note_ids = parse_fields_packed(&pending_note_ids, "pending note ids")?;
        self.build_pending_commitment_fields(batch_size, pending_note_ids)
    }

    fn build_pending_commitment_fields(
        &mut self,
        batch_size: u32,
        pending_note_ids: Vec<curvy_core::Fr>,
    ) -> Result<PendingCommitmentInput> {
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

#[napi(catch_unwind)]
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
    let values: Vec<String> = serde_json::from_str(json).map_err(|_| {
        Error::new(
            Status::InvalidArg,
            format!("expected {label} as a JSON array of decimal strings"),
        )
    })?;
    values
        .iter()
        .map(|value| {
            Bn254Fr::try_from_dec(value)
                .map(Bn254Fr::into_inner)
                .map_err(|error| native_error(&format!("parse {label} field element"), error))
        })
        .collect()
}

fn parse_fields_packed(bytes: &[u8], label: &str) -> Result<Vec<curvy_core::Fr>> {
    if !bytes.len().is_multiple_of(32) {
        return Err(Error::new(
            Status::InvalidArg,
            format!("packed {label} length must be a multiple of 32 bytes"),
        ));
    }
    bytes
        .chunks_exact(32)
        .enumerate()
        .map(|(index, bytes)| {
            let encoded: &[u8; 32] = bytes
                .try_into()
                .expect("chunks_exact(32) always yields 32 bytes");
            fr_from_be_32_checked(encoded).ok_or_else(|| {
                Error::new(
                    Status::InvalidArg,
                    format!("packed {label} field element {index} is not canonical"),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn initialization_does_not_start_the_global_rayon_pool() {
        // A valid graph with four assignment signals, matching multiplier.zkey.
        let mut graph = b"SIGNET01".to_vec();
        graph.extend(1_u16.to_le_bytes());
        graph.extend(1_u16.to_le_bytes());
        graph.extend(64_u32.to_le_bytes());
        graph.extend([0; 32]);
        for count in [1_u32, 4, 0, 1] {
            graph.extend(count.to_le_bytes());
        }
        graph.extend([0; 5]); // Constant-one input node.
        graph.extend([0; 16]); // Four references to that node.
        let path =
            std::env::temp_dir().join(format!("curvy-node-pool-{}.graph", std::process::id()));
        fs::write(&path, graph).unwrap();
        let result = ResidentProver::initialize(ResidentProverOptions {
            zkey_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../crates/prover/testdata/multiplier.zkey"
            )
            .into(),
            zkey_sha256: "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f".into(),
            witness_graph_path: Some(path.to_string_lossy().into_owned()),
            witness_graph_sha256:
                "ee23155298ce2e491b9031d57fe4b63ce6618f7b4013da89737579abdd019d6f".into(),
            threads: Some(1),
            max_pending_proofs: None,
            use_sage: None,
            sage_program_path: None,
            sage_program_sha256: None,
            zkey_manifest_path: None,
            zkey_manifest_sha256: None,
        });
        fs::remove_file(path).unwrap();
        let prover = result.expect("fixture must initialize");
        assert_eq!(prover.thread_pool.install(rayon::current_num_threads), 1);
        // Rayon only allows this once. If key parsing escaped the private pool,
        // its parallel iterators would already have initialized the global one.
        ThreadPoolBuilder::new()
            .num_threads(1)
            .build_global()
            .expect("initialization must leave the process-wide Rayon pool untouched");
    }
}
