#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
//!
//! ## Security model
//!
//! The proving key parser is the committed `rs-core` implementation vendored
//! from `ark-circom` without its Wasmer witness calculator. Bulk query points are
//! constructed unchecked for fast startup, so every caller must provide a pinned
//! SHA-256 digest for the zkey. Whole-key native loads authenticate before parsing,
//! and one-pass manifest loads authenticate each chunk before parsing. The browser
//! two-response fallback authenticates its first response up front and hashes the
//! second response while parsing; its final digest check and self-verification gate
//! the result, but the second response still crosses the parser before that check.
//!
//! Native builds enable `std` and use stock serial ark-groth16 by default.
//! The opt-in `parallel` feature uses Curvy's global-pool proof path. Portable
//! WASM uses the `wasm` feature; threaded browser builds use `wasm-threads` and
//! export `initThreadPool(n)` so the host selects the worker count explicitly.

pub mod qap;
#[cfg(feature = "sparrow")]
pub mod sparrow;
pub mod wtns;
pub mod zkey;

#[cfg(feature = "parallel")]
mod groth16_prover;
#[cfg(any(feature = "parallel", feature = "sparrow"))]
mod msm;

use std::io::Cursor;

use ark_bn254::{Bn254, Fq, Fq2, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, prepare_verifying_key};
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::SerializationError;
use curvy_witness::{WitnessError, WitnessGraph};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use thiserror::Error;

use wtns::WtnsError;
use zkey::ZkeyMatrices;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("expected zkey SHA-256 must be exactly 64 hexadecimal characters")]
    InvalidExpectedHash,
    #[error("zkey SHA-256 mismatch: expected {expected}, got {actual}")]
    ZkeyHashMismatch { expected: String, actual: String },
    #[error("invalid zkey: {0}")]
    InvalidZkey(SerializationError),
    #[error(transparent)]
    InvalidWitness(#[from] WtnsError),
    #[error(transparent)]
    InvalidWitnessGraph(#[from] WitnessError),
    #[error("witness assignment length mismatch: expected {expected}, got {actual}")]
    AssignmentLength { expected: usize, actual: usize },
    #[error("Groth16 proof generation failed: {0}")]
    ProofGeneration(SynthesisError),
    #[error("Groth16 verification failed: {0}")]
    Verification(SynthesisError),
    #[error("generated Groth16 proof did not verify")]
    SelfVerificationFailed,
}

/// Parsed, reusable proving key and constraint matrices for one circuit.
pub struct Prover {
    pk: ProvingKey<Bn254>,
    matrices: ZkeyMatrices<Fr>,
    pvk: PreparedVerifyingKey<Bn254>,
    assignment_size: usize,
}

impl Prover {
    /// Authenticate and parse one zkey. Hash verification happens before the
    /// unchecked point parser sees any artifact-controlled curve coordinates.
    pub fn from_zkey_bytes(bytes: &[u8], expected_sha256: &str) -> Result<Self, ProverError> {
        verify_sha256(bytes, expected_sha256)?;
        let mut cursor = Cursor::new(bytes);
        let (pk, matrices) = zkey::read_zkey(&mut cursor).map_err(ProverError::InvalidZkey)?;
        let pvk = prepare_verifying_key(&pk.vk);
        let assignment_size = pk.a_query.len();
        Ok(Self {
            pk,
            matrices,
            pvk,
            assignment_size,
        })
    }

    pub fn num_constraints(&self) -> usize {
        self.matrices.num_constraints
    }

    pub fn num_public(&self) -> usize {
        self.matrices.num_instance_variables.saturating_sub(1)
    }

    pub fn prove(&self, full_assignment: &[Fr]) -> Result<Proof<Bn254>, ProverError> {
        self.validate_assignment(full_assignment)?;
        let mut rng = ark_std::rand::rngs::OsRng;
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        #[cfg(feature = "parallel")]
        let proof = groth16_prover::create_proof_with_matrices(
            &self.pk,
            r,
            s,
            &self.matrices.matrices,
            self.matrices.num_instance_variables,
            self.matrices.num_constraints,
            full_assignment,
        );

        #[cfg(not(feature = "parallel"))]
        let proof =
            Groth16::<Bn254, qap::CircomReduction>::create_proof_with_reduction_and_matrices(
                &self.pk,
                r,
                s,
                &self.matrices.matrices,
                self.matrices.num_instance_variables,
                self.matrices.num_constraints,
                full_assignment,
            );

        proof.map_err(ProverError::ProofGeneration)
    }

    pub fn public_inputs<'a>(&self, full_assignment: &'a [Fr]) -> Result<&'a [Fr], ProverError> {
        self.validate_assignment(full_assignment)?;
        Ok(&full_assignment[1..self.matrices.num_instance_variables])
    }

    pub fn verify(&self, proof: &Proof<Bn254>, public_inputs: &[Fr]) -> Result<bool, ProverError> {
        Groth16::<Bn254>::verify_proof(&self.pvk, proof, public_inputs)
            .map_err(ProverError::Verification)
    }

    /// Decode, prove, and self-verify one snarkjs witness before returning it.
    pub fn prove_wtns(&self, bytes: &[u8]) -> Result<ProofBundle, ProverError> {
        let assignment = wtns::read_wtns(bytes)?;
        self.prove_assignment(&assignment)
    }

    /// Prove and self-verify one direct arkworks witness assignment.
    pub fn prove_assignment(&self, assignment: &[Fr]) -> Result<ProofBundle, ProverError> {
        let proof = self.prove(assignment)?;
        let public_inputs = self.public_inputs(assignment)?;
        if !self.verify(&proof, public_inputs)? {
            return Err(ProverError::SelfVerificationFailed);
        }
        Ok(ProofBundle {
            proof_json: proof_to_snarkjs_json(&proof),
            public_signals_json: publics_to_json(public_inputs),
        })
    }

    fn validate_assignment(&self, full_assignment: &[Fr]) -> Result<(), ProverError> {
        self.validate_assignment_size(full_assignment.len())
    }

    fn validate_assignment_size(&self, actual: usize) -> Result<(), ProverError> {
        if actual != self.assignment_size {
            return Err(ProverError::AssignmentLength {
                expected: self.assignment_size,
                actual,
            });
        }
        Ok(())
    }
}

/// Authenticated witness graph and proving key for one immutable circuit bundle.
pub struct CircuitProver {
    prover: Prover,
    witness_graph: WitnessGraph,
}

impl CircuitProver {
    pub fn from_artifacts(
        zkey: &[u8],
        expected_zkey_sha256: &str,
        witness_graph: &[u8],
        expected_graph_sha256: &str,
    ) -> Result<Self, ProverError> {
        let prover = Prover::from_zkey_bytes(zkey, expected_zkey_sha256)?;
        let witness_graph = WitnessGraph::from_bytes(witness_graph, expected_graph_sha256)?;
        prover.validate_assignment_size(witness_graph.assignment_size())?;
        Ok(Self {
            prover,
            witness_graph,
        })
    }

    pub fn num_constraints(&self) -> usize {
        self.prover.num_constraints()
    }

    pub fn num_public(&self) -> usize {
        self.prover.num_public()
    }

    pub fn r1cs_sha256(&self) -> [u8; 32] {
        self.witness_graph.r1cs_sha256()
    }

    /// Evaluate authenticated `curvy-graph-v1` inputs without proving yet.
    ///
    /// This split is useful to native operators that report witness and proof
    /// timings separately. Most callers should use [`Self::prove_json`].
    pub fn calculate_witness_json(&self, input_json: &str) -> Result<Vec<Fr>, ProverError> {
        Ok(self.witness_graph.calculate_json(input_json)?)
    }

    /// Prove and self-verify an assignment produced by this circuit's graph.
    pub fn prove_assignment(&self, assignment: &[Fr]) -> Result<ProofBundle, ProverError> {
        self.prover.prove_assignment(assignment)
    }

    pub fn prove_json(&self, input_json: &str) -> Result<ProofBundle, ProverError> {
        let assignment = self.calculate_witness_json(input_json)?;
        self.prove_assignment(&assignment)
    }
}

pub struct ProofBundle {
    pub proof_json: String,
    pub public_signals_json: String,
}

fn verify_sha256(bytes: &[u8], expected_sha256: &str) -> Result<(), ProverError> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProverError::InvalidExpectedHash);
    }
    let expected = expected_sha256.to_ascii_lowercase();
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected {
        return Err(ProverError::ZkeyHashMismatch { expected, actual });
    }
    Ok(())
}

fn fq_dec(value: &Fq) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_str_radix(10)
}

fn fr_dec(value: &Fr) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_str_radix(10)
}

fn fq2_json(value: &Fq2) -> String {
    format!("[\"{}\",\"{}\"]", fq_dec(&value.c0), fq_dec(&value.c1))
}

/// Serialize a proof with the same coordinate order and shape as snarkjs.
pub fn proof_to_snarkjs_json(proof: &Proof<Bn254>) -> String {
    format!(
        "{{\"pi_a\":[\"{}\",\"{}\",\"1\"],\"pi_b\":[{}, {},[\"1\",\"0\"]],\"pi_c\":[\"{}\",\"{}\",\"1\"],\"protocol\":\"groth16\",\"curve\":\"bn128\"}}",
        fq_dec(&proof.a.x),
        fq_dec(&proof.a.y),
        fq2_json(&proof.b.x),
        fq2_json(&proof.b.y),
        fq_dec(&proof.c.x),
        fq_dec(&proof.c.y),
    )
}

pub fn publics_to_json(publics: &[Fr]) -> String {
    let items = publics
        .iter()
        .map(|public| format!("\"{}\"", fr_dec(public)))
        .collect::<Vec<_>>();
    format!("[{}]", items.join(","))
}

#[cfg(feature = "wasm-threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(feature = "wasm")]
mod wasm_api {
    #[cfg(feature = "sparrow")]
    use ark_bn254::Fr;
    use wasm_bindgen::prelude::*;

    #[cfg(feature = "sparrow")]
    use crate::sparrow::{
        SparrowAuthenticator, SparrowConfig, SparrowProofBuilder, SparrowProver,
        manifest::{ManifestProofStream, ZkeyChunkManifest},
    };

    /// Invalidate origin-local SAGE caches when compiler semantics change.
    #[cfg(feature = "sparrow")]
    #[wasm_bindgen(js_name = sageCacheVersion)]
    pub fn sage_cache_version() -> u32 {
        curvy_witness::sage::CACHE_VERSION
    }

    /// Identical kernels used by the native and browser phase benchmarks.
    #[cfg(feature = "bench")]
    #[wasm_bindgen(js_name = benchSha256)]
    pub fn bench_sha256(bytes: u32, rounds: u32) -> Result<u32, JsError> {
        crate::sparrow::phase_bench::sha256(bytes as usize, rounds as usize).map_err(js_error)
    }

    #[cfg(feature = "bench")]
    #[wasm_bindgen(js_name = benchFieldArithmetic)]
    pub fn bench_field_arithmetic(iterations: u32) -> Result<u32, JsError> {
        crate::sparrow::phase_bench::field_multiplication(iterations as usize).map_err(js_error)
    }

    #[cfg(feature = "bench")]
    #[wasm_bindgen(js_name = benchFft)]
    pub fn bench_fft(log_size: u32, rounds: u32) -> Result<u32, JsError> {
        crate::sparrow::phase_bench::fft(log_size, rounds as usize).map_err(js_error)
    }

    #[cfg(feature = "bench")]
    #[wasm_bindgen(js_name = benchG1Msm)]
    pub fn bench_g1_msm(log_size: u32, window_bits: u32) -> Result<u32, JsError> {
        crate::sparrow::phase_bench::g1_msm(log_size, window_bits as usize).map_err(js_error)
    }

    #[cfg(feature = "bench")]
    #[wasm_bindgen(js_name = benchG2Msm)]
    pub fn bench_g2_msm(log_size: u32, window_bits: u32) -> Result<u32, JsError> {
        crate::sparrow::phase_bench::g2_msm(log_size, window_bits as usize).map_err(js_error)
    }

    #[wasm_bindgen]
    pub struct WasmWitnessGraph(curvy_witness::WitnessGraph);

    #[wasm_bindgen]
    impl WasmWitnessGraph {
        /// Authenticate and decode a witness graph without loading a proving key.
        ///
        /// This is also the cross-target conformance surface for SIGNET: the
        /// native and WebAssembly tests feed identical v1/v2 artifacts and inputs
        /// through the same `curvy-witness` implementation.
        #[wasm_bindgen(constructor)]
        pub fn new(
            witness_graph: &[u8],
            expected_graph_sha256: &str,
            batch_profile: bool,
        ) -> Result<WasmWitnessGraph, JsError> {
            let limits = if batch_profile {
                curvy_witness::Limits::batch_prover()
            } else {
                curvy_witness::Limits::client()
            };
            curvy_witness::WitnessGraph::from_bytes_with_limits(
                witness_graph,
                expected_graph_sha256,
                limits,
            )
            .map(WasmWitnessGraph)
            .map_err(|error| JsError::new(&error.to_string()))
        }

        #[wasm_bindgen(getter, js_name = assignmentSize)]
        pub fn assignment_size(&self) -> usize {
            self.0.assignment_size()
        }

        /// Return the complete assignment as decimal strings.
        pub fn calculate(&self, input_json: &str) -> Result<String, JsError> {
            self.0
                .calculate_json(input_json)
                .map(|assignment| crate::publics_to_json(&assignment))
                .map_err(|error| JsError::new(&error.to_string()))
        }
    }

    #[wasm_bindgen]
    pub struct WasmCircuitProver(crate::CircuitProver);

    #[wasm_bindgen]
    impl WasmCircuitProver {
        #[wasm_bindgen(constructor)]
        pub fn new(
            zkey: &[u8],
            expected_zkey_sha256: &str,
            witness_graph: &[u8],
            expected_graph_sha256: &str,
        ) -> Result<WasmCircuitProver, JsError> {
            crate::CircuitProver::from_artifacts(
                zkey,
                expected_zkey_sha256,
                witness_graph,
                expected_graph_sha256,
            )
            .map(WasmCircuitProver)
            .map_err(|error| JsError::new(&error.to_string()))
        }

        #[wasm_bindgen(getter, js_name = numConstraints)]
        pub fn num_constraints(&self) -> usize {
            self.0.num_constraints()
        }

        #[wasm_bindgen(getter, js_name = numPublic)]
        pub fn num_public(&self) -> usize {
            self.0.num_public()
        }

        /// Calculate, prove, and self-verify directly from circuit input JSON.
        pub fn prove(&self, input_json: &str) -> Result<String, JsError> {
            self.0
                .prove_json(input_json)
                .map(bundle_json)
                .map_err(|error| JsError::new(&error.to_string()))
        }
    }

    /// SPARROW's SAGE witness evaluation and bounded-memory zkey processing.
    ///
    /// Browser flow: feed the first cached `Response.body` to
    /// `authenticateZkeyChunk`, call `finishZkeyAuthentication`, reopen the
    /// response, then frame its 12-byte file/section headers and feed each
    /// section body to the matching proof methods.
    #[cfg(feature = "sparrow")]
    #[wasm_bindgen]
    pub struct WasmSparrowProver {
        prover: Option<SparrowProver>,
        assignment_size: usize,
        sage_slots: usize,
        expected_zkey_sha256: String,
        config: SparrowConfig,
        authenticator: Option<SparrowAuthenticator>,
        authenticated: bool,
        proof: Option<SparrowProofBuilder>,
        manifest_proof: Option<ManifestProofStream>,
    }

    #[cfg(feature = "sparrow")]
    #[wasm_bindgen]
    impl WasmSparrowProver {
        #[wasm_bindgen(constructor)]
        pub fn new(
            witness_graph: &[u8],
            expected_graph_sha256: &str,
            expected_zkey_sha256: &str,
            batch_profile: bool,
        ) -> Result<WasmSparrowProver, JsError> {
            let config = SparrowConfig::default();
            Self::from_signet_with_config(
                witness_graph,
                expected_graph_sha256,
                expected_zkey_sha256,
                batch_profile,
                config.window_bits as u32,
                config.msm_chunk_points as u32,
            )
        }

        /// Compile an authenticated SIGNET graph with explicit MSM tuning.
        #[wasm_bindgen(js_name = fromSignetWithConfig)]
        pub fn from_signet_with_config(
            witness_graph: &[u8],
            expected_graph_sha256: &str,
            expected_zkey_sha256: &str,
            batch_profile: bool,
            window_bits: u32,
            msm_chunk_points: u32,
        ) -> Result<WasmSparrowProver, JsError> {
            let config = SparrowConfig {
                window_bits: window_bits as usize,
                msm_chunk_points: msm_chunk_points as usize,
                ..SparrowConfig::default()
            };
            let limits = if batch_profile {
                curvy_witness::Limits::batch_prover()
            } else {
                curvy_witness::Limits::client()
            };
            let prover = SparrowProver::from_signet_bytes(
                witness_graph,
                expected_graph_sha256,
                expected_zkey_sha256,
                limits,
                config,
            )
            .map_err(js_error)?;
            let authenticator = SparrowAuthenticator::new(expected_zkey_sha256)
                .map(Some)
                .map_err(js_error)?;
            let assignment_size = prover.assignment_size();
            let sage_slots = prover.sage_slot_count();
            Ok(Self {
                prover: Some(prover),
                assignment_size,
                sage_slots,
                expected_zkey_sha256: expected_zkey_sha256.to_ascii_lowercase(),
                config,
                authenticator,
                authenticated: false,
                proof: None,
                manifest_proof: None,
            })
        }

        #[wasm_bindgen(js_name = fromCompiledSage)]
        pub fn from_compiled_sage(
            sage_program: &[u8],
            expected_program_sha256: &str,
            expected_source_graph_sha256: &str,
            expected_zkey_sha256: &str,
            batch_profile: bool,
        ) -> Result<WasmSparrowProver, JsError> {
            let config = SparrowConfig::default();
            Self::from_compiled_sage_with_config(
                sage_program,
                expected_program_sha256,
                expected_source_graph_sha256,
                expected_zkey_sha256,
                batch_profile,
                config.window_bits as u32,
                config.msm_chunk_points as u32,
            )
        }

        /// Benchmark/advanced constructor for target-specific MSM tuning.
        ///
        /// `window_bits` accepts 0 for the query-size adaptive policy or an
        /// explicit width in `4..=16`. Browser deployments should prefer a
        /// fixed value measured on their target devices.
        #[wasm_bindgen(js_name = fromCompiledSageWithConfig)]
        pub fn from_compiled_sage_with_config(
            sage_program: &[u8],
            expected_program_sha256: &str,
            expected_source_graph_sha256: &str,
            expected_zkey_sha256: &str,
            batch_profile: bool,
            window_bits: u32,
            msm_chunk_points: u32,
        ) -> Result<WasmSparrowProver, JsError> {
            let config = SparrowConfig {
                window_bits: window_bits as usize,
                msm_chunk_points: msm_chunk_points as usize,
                ..SparrowConfig::default()
            };
            let limits = if batch_profile {
                curvy_witness::Limits::batch_prover()
            } else {
                curvy_witness::Limits::client()
            };
            let prover = SparrowProver::from_compiled_sage_bytes(
                sage_program,
                expected_program_sha256,
                expected_source_graph_sha256,
                expected_zkey_sha256,
                limits,
                config,
            )
            .map_err(js_error)?;
            let assignment_size = prover.assignment_size();
            let sage_slots = prover.sage_slot_count();
            Ok(Self {
                prover: Some(prover),
                assignment_size,
                sage_slots,
                expected_zkey_sha256: expected_zkey_sha256.to_ascii_lowercase(),
                config,
                authenticator: Some(
                    SparrowAuthenticator::new(expected_zkey_sha256).map_err(js_error)?,
                ),
                authenticated: false,
                proof: None,
                manifest_proof: None,
            })
        }

        #[wasm_bindgen(getter, js_name = assignmentSize)]
        pub fn assignment_size(&self) -> usize {
            self.assignment_size
        }

        #[wasm_bindgen(getter, js_name = sageSlots)]
        pub fn sage_slots(&self) -> usize {
            self.sage_slots
        }

        /// Serialize the program produced from an authenticated source graph.
        /// JavaScript should cache it under `sageCacheVersion()` plus that source
        /// digest, then load it through `fromCompiledSageWithConfig`.
        #[wasm_bindgen(js_name = compiledSageProgram)]
        pub fn compiled_sage_program(&self) -> Result<Vec<u8>, JsError> {
            self.prover
                .as_ref()
                .ok_or_else(|| JsError::new("the one-shot SAGE graph has already been released"))?
                .compiled_sage_bytes()
                .map_err(js_error)
        }

        #[wasm_bindgen(js_name = authenticateZkeyChunk)]
        pub fn authenticate_zkey_chunk(&mut self, bytes: &[u8]) -> Result<(), JsError> {
            self.authenticator
                .as_mut()
                .ok_or_else(|| JsError::new("zkey authentication pass is already complete"))?
                .update(bytes)
                .map_err(js_error)
        }

        #[wasm_bindgen(js_name = finishZkeyAuthentication)]
        pub fn finish_zkey_authentication(&mut self) -> Result<u64, JsError> {
            let bytes = self
                .authenticator
                .take()
                .ok_or_else(|| JsError::new("zkey authentication pass is already complete"))?
                .finish()
                .map_err(js_error)?;
            self.authenticated = true;
            Ok(bytes)
        }

        #[wasm_bindgen(js_name = beginProof)]
        pub fn begin_proof(&mut self, input_json: &str) -> Result<(), JsError> {
            if !self.authenticated {
                return Err(JsError::new(
                    "authenticate the zkey before beginning a proof",
                ));
            }
            if self.proof.is_some() || self.manifest_proof.is_some() {
                return Err(JsError::new("a SPARROW proof is already active"));
            }
            let assignment = self
                .prover
                .as_ref()
                .ok_or_else(|| JsError::new("the one-shot SAGE graph has already been released"))?
                .calculate_witness_json(input_json)
                .map_err(js_error)?;
            self.install_proof(assignment)
        }

        /// Evaluate once and release the compiled SAGE program before the QAP
        /// and MSM phases. Mobile callers that do not reuse a circuit should
        /// prefer this so the graph's instruction storage can be recycled.
        #[wasm_bindgen(js_name = beginOneShotProof)]
        pub fn begin_one_shot_proof(&mut self, input_json: &str) -> Result<(), JsError> {
            if !self.authenticated {
                return Err(JsError::new(
                    "authenticate the zkey before beginning a proof",
                ));
            }
            if self.proof.is_some() || self.manifest_proof.is_some() {
                return Err(JsError::new("a SPARROW proof is already active"));
            }
            let proof = build_then_release(&mut self.prover, |prover| {
                let assignment = prover.calculate_witness_json(input_json)?;
                SparrowProofBuilder::new(assignment, &self.expected_zkey_sha256, self.config)
            })
            .ok_or_else(|| JsError::new("the one-shot SAGE graph has already been released"))?
            .map_err(js_error)?;
            self.proof = Some(proof);
            Ok(())
        }

        fn install_proof(&mut self, assignment: Vec<Fr>) -> Result<(), JsError> {
            self.proof = Some(
                SparrowProofBuilder::new(assignment, &self.expected_zkey_sha256, self.config)
                    .map_err(js_error)?,
            );
            Ok(())
        }

        /// Begin a one-pass proof. The small chunk manifest is authenticated
        /// up front; each zkey chunk is then checked before parsing.
        #[wasm_bindgen(js_name = beginOneShotManifestProof)]
        pub fn begin_one_shot_manifest_proof(
            &mut self,
            input_json: &str,
            manifest_bytes: &[u8],
            expected_manifest_sha256: &str,
        ) -> Result<(), JsError> {
            if self.proof.is_some() || self.manifest_proof.is_some() {
                return Err(JsError::new("a SPARROW proof is already active"));
            }
            let manifest = ZkeyChunkManifest::from_bytes(
                manifest_bytes,
                expected_manifest_sha256,
                &self.expected_zkey_sha256,
            )
            .map_err(js_error)?;
            let manifest_proof = build_then_release(&mut self.prover, |prover| {
                let assignment = prover.calculate_witness_json(input_json)?;
                ManifestProofStream::new(assignment, manifest, self.config)
            })
            .ok_or_else(|| JsError::new("the one-shot SAGE graph has already been released"))?
            .map_err(js_error)?;
            self.manifest_proof = Some(manifest_proof);
            Ok(())
        }

        #[wasm_bindgen(js_name = pushManifestZkeyChunk)]
        pub fn push_manifest_zkey_chunk(&mut self, bytes: Vec<u8>) -> Result<(), JsError> {
            self.manifest_proof
                .as_mut()
                .ok_or_else(|| JsError::new("no manifest-authenticated proof is active"))?
                .push_complete_chunk(bytes)
                .map_err(js_error)
        }

        #[wasm_bindgen(js_name = finishManifestProof)]
        pub fn finish_manifest_proof(&mut self) -> Result<String, JsError> {
            self.manifest_proof
                .take()
                .ok_or_else(|| JsError::new("no manifest-authenticated proof is active"))?
                .finish()
                .map(bundle_json)
                .map_err(js_error)
        }

        #[wasm_bindgen(js_name = beginZkey)]
        pub fn begin_zkey(&mut self, header: &[u8]) -> Result<(), JsError> {
            proof_mut(self)?.begin_zkey(header).map_err(js_error)
        }

        #[wasm_bindgen(js_name = beginZkeySection)]
        pub fn begin_zkey_section(&mut self, header: &[u8]) -> Result<(), JsError> {
            proof_mut(self)?.begin_section(header).map_err(js_error)
        }

        #[wasm_bindgen(js_name = pushZkeySectionChunk)]
        pub fn push_zkey_section_chunk(&mut self, bytes: &[u8]) -> Result<(), JsError> {
            proof_mut(self)?.push_section_chunk(bytes).map_err(js_error)
        }

        #[wasm_bindgen(js_name = endZkeySection)]
        pub fn end_zkey_section(&mut self) -> Result<(), JsError> {
            proof_mut(self)?.end_section().map_err(js_error)
        }

        #[wasm_bindgen(js_name = finishProof)]
        pub fn finish_proof(&mut self) -> Result<String, JsError> {
            self.proof
                .take()
                .ok_or_else(|| JsError::new("no SPARROW proof is active"))?
                .finish()
                .map(bundle_json)
                .map_err(js_error)
        }
    }

    #[cfg(feature = "sparrow")]
    fn proof_mut(prover: &mut WasmSparrowProver) -> Result<&mut SparrowProofBuilder, JsError> {
        prover
            .proof
            .as_mut()
            .ok_or_else(|| JsError::new("no SPARROW proof is active"))
    }

    #[cfg(feature = "sparrow")]
    fn js_error(error: impl std::fmt::Display) -> JsError {
        JsError::new(&error.to_string())
    }

    /// Run every fallible one-shot preparation step before releasing a large
    /// reusable value. This keeps invalid user input retryable without cloning
    /// the compiled SAGE evaluator.
    #[cfg(feature = "sparrow")]
    fn build_then_release<T, U, E>(
        source: &mut Option<T>,
        build: impl FnOnce(&T) -> Result<U, E>,
    ) -> Option<Result<U, E>> {
        let result = build(source.as_ref()?);
        if result.is_ok() {
            drop(source.take());
        }
        Some(result)
    }

    #[cfg(all(test, feature = "sparrow"))]
    mod tests {
        use super::build_then_release;

        #[test]
        fn one_shot_state_is_released_only_after_successful_preparation() {
            let mut source = Some(7_u32);
            let failed = build_then_release(&mut source, |_| Err::<(), _>("invalid input"));
            assert_eq!(failed, Some(Err("invalid input")));
            assert_eq!(source, Some(7));

            let built = build_then_release(&mut source, |value| Ok::<_, &str>(value + 1));
            assert_eq!(built, Some(Ok(8)));
            assert_eq!(source, None);
        }
    }

    #[wasm_bindgen]
    pub struct WasmProver(crate::Prover);

    #[wasm_bindgen]
    impl WasmProver {
        #[wasm_bindgen(constructor)]
        pub fn new(zkey: &[u8], expected_sha256: &str) -> Result<WasmProver, JsError> {
            crate::Prover::from_zkey_bytes(zkey, expected_sha256)
                .map(WasmProver)
                .map_err(|error| JsError::new(&error.to_string()))
        }

        #[wasm_bindgen(getter, js_name = numConstraints)]
        pub fn num_constraints(&self) -> usize {
            self.0.num_constraints()
        }

        #[wasm_bindgen(getter, js_name = numPublic)]
        pub fn num_public(&self) -> usize {
            self.0.num_public()
        }

        /// Return `{"proof": ..., "publicSignals": [...]}` in snarkjs shape.
        pub fn prove(&self, wtns: &[u8]) -> Result<String, JsError> {
            self.0
                .prove_wtns(wtns)
                .map(bundle_json)
                .map_err(|error| JsError::new(&error.to_string()))
        }
    }

    fn bundle_json(bundle: crate::ProofBundle) -> String {
        format!(
            "{{\"proof\":{},\"publicSignals\":{}}}",
            bundle.proof_json, bundle.public_signals_json
        )
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{Prover, ProverError, verify_sha256};

    #[test]
    fn rejects_an_untrusted_zkey_before_parsing() {
        let error = verify_sha256(b"not a zkey", &"00".repeat(32)).expect_err("hash must mismatch");
        assert!(matches!(error, ProverError::ZkeyHashMismatch { .. }));
    }

    #[test]
    fn rejects_a_malformed_expected_hash() {
        assert!(matches!(
            verify_sha256(b"anything", "not-a-digest"),
            Err(ProverError::InvalidExpectedHash)
        ));
    }

    #[test]
    fn rejects_malformed_zkey_after_its_digest_matches() {
        let bytes = b"not a zkey";
        let digest = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let error = Prover::from_zkey_bytes(bytes, &digest)
            .err()
            .expect("zkey parser must reject junk");
        assert!(matches!(error, ProverError::InvalidZkey(_)));
    }
}
