#[cfg(feature = "sparrow")]
use ark_bn254::Fr;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[cfg(feature = "sparrow")]
use crate::sparrow::{
    StreamingAuthenticator, StreamingConfig, StreamingProofBuilder, StreamingProver,
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
    pub fn calculate(&self, input_json: String) -> Result<String, JsError> {
        let input_json = Zeroizing::new(input_json);
        self.0
            .calculate_json(&input_json)
            .map(|assignment| crate::publics_to_json(&assignment))
            .map_err(|error| JsError::new(&error.to_string()))
    }

    /// Return the complete assignment as concatenated canonical 32-byte
    /// big-endian field elements, without decimal or JSON conversion.
    #[wasm_bindgen(js_name = calculatePacked)]
    pub fn calculate_packed(&self, input_json: String) -> Result<Vec<u8>, JsError> {
        let input_json = Zeroizing::new(input_json);
        self.0
            .calculate_json(&input_json)
            .map(|assignment| crate::assignment_to_packed_be(&assignment))
            .map_err(|error| JsError::new(&error.to_string()))
    }
}

#[wasm_bindgen]
pub struct WasmResidentProver(crate::ResidentProver);

#[wasm_bindgen]
impl WasmResidentProver {
    #[wasm_bindgen(constructor)]
    pub fn new(
        zkey: &[u8],
        expected_zkey_sha256: &str,
        witness_graph: &[u8],
        expected_graph_sha256: &str,
    ) -> Result<WasmResidentProver, JsError> {
        crate::ResidentProver::from_artifacts(
            zkey,
            expected_zkey_sha256,
            witness_graph,
            expected_graph_sha256,
        )
        .map(WasmResidentProver)
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

    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> String {
        self.0.mode().as_str().to_owned()
    }

    #[wasm_bindgen(getter)]
    pub fn profile(&self) -> String {
        self.0.profile().to_owned()
    }

    /// SHA-256 of the loaded key's verifying key. Compare it against the
    /// deployed verifier before submitting proofs.
    #[wasm_bindgen(getter, js_name = verifyingKeyDigest)]
    pub fn verifying_key_digest(&self) -> String {
        self.0.verifying_key_digest()
    }

    /// Calculate, prove, and self-verify directly from circuit input JSON.
    pub fn prove(&self, input_json: String) -> Result<String, JsError> {
        let input_json = Zeroizing::new(input_json);
        self.0
            .prove_json(&input_json)
            .map(bundle_json)
            .map_err(|error| JsError::new(&error.to_string()))
    }
}

/// SPARROW's SAGE witness evaluation and bounded-memory zkey processing.
///
/// Browser flow: feed the first cached `Response.body` to
/// `authenticateZkeyChunk`, call `finishZkeyAuthentication`, reopen the
/// response through the checked browser adapter, then frame its headers.
/// Raw framing methods require pre-authenticated bytes; a final digest alone
/// does not prevent malformed input from reaching arithmetic or allocations.
///
/// A failed digest check restarts the authentication pass, and
/// `resetZkeyAuthentication` discards a partial one. A failed proof stream
/// must call `abortProof` before the next begin; a reusable prover can then
/// prove again, while a one-shot begin has already released its graph.
#[cfg(feature = "sparrow")]
#[wasm_bindgen]
pub struct WasmStreamingProver {
    prover: Option<StreamingProver>,
    assignment_size: usize,
    sage_slots: usize,
    expected_zkey_sha256: String,
    config: StreamingConfig,
    authenticator: Option<StreamingAuthenticator>,
    authenticated: bool,
    authenticated_bytes: u64,
    proof: Option<StreamingProofBuilder>,
    manifest_proof: Option<ManifestProofStream>,
}

#[cfg(feature = "sparrow")]
#[wasm_bindgen]
impl WasmStreamingProver {
    #[wasm_bindgen(constructor)]
    pub fn new(
        witness_graph: &[u8],
        expected_graph_sha256: &str,
        expected_zkey_sha256: &str,
        batch_profile: bool,
    ) -> Result<WasmStreamingProver, JsError> {
        let config = StreamingConfig::default();
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
    ) -> Result<WasmStreamingProver, JsError> {
        let config = StreamingConfig {
            window_bits: window_bits as usize,
            msm_chunk_points: msm_chunk_points as usize,
            ..StreamingConfig::default()
        };
        let limits = if batch_profile {
            curvy_witness::Limits::batch_prover()
        } else {
            curvy_witness::Limits::client()
        };
        let prover = StreamingProver::from_signet_bytes(
            witness_graph,
            expected_graph_sha256,
            expected_zkey_sha256,
            limits,
            config,
        )
        .map_err(js_error)?;
        let authenticator = StreamingAuthenticator::new(expected_zkey_sha256)
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
            authenticated_bytes: 0,
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
    ) -> Result<WasmStreamingProver, JsError> {
        let config = StreamingConfig::default();
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
    ) -> Result<WasmStreamingProver, JsError> {
        let config = StreamingConfig {
            window_bits: window_bits as usize,
            msm_chunk_points: msm_chunk_points as usize,
            ..StreamingConfig::default()
        };
        let limits = if batch_profile {
            curvy_witness::Limits::batch_prover()
        } else {
            curvy_witness::Limits::client()
        };
        let prover = StreamingProver::from_compiled_sage_bytes(
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
                StreamingAuthenticator::new(expected_zkey_sha256).map_err(js_error)?,
            ),
            authenticated: false,
            authenticated_bytes: 0,
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

    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> String {
        crate::ProverMode::Streaming.as_str().to_owned()
    }

    #[wasm_bindgen(getter)]
    pub fn profile(&self) -> String {
        crate::SPARROW_PROFILE.to_owned()
    }

    /// Serialize the program produced from an authenticated source graph.
    /// JavaScript should cache it under `sageCacheVersion()` plus that source
    /// digest, then load it through `fromCompiledSageWithConfig`.
    #[wasm_bindgen(js_name = compiledSageProgram)]
    pub fn compiled_sage_program(&self) -> Result<Vec<u8>, JsError> {
        self.prover
            .as_ref()
            .ok_or_else(|| JsError::new(GRAPH_RELEASED))?
            .compiled_sage_bytes()
            .map_err(js_error)
    }

    /// Whether a whole-file zkey authentication pass has completed and has not
    /// been reset since.
    #[wasm_bindgen(getter, js_name = zkeyAuthenticated)]
    pub fn zkey_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Whether a framed or manifest-authenticated proof is in progress.
    #[wasm_bindgen(getter, js_name = proofActive)]
    pub fn proof_active(&self) -> bool {
        self.proof.is_some() || self.manifest_proof.is_some()
    }

    /// Whether a one-shot proof has released the compiled SAGE graph. A
    /// released prover cannot begin another proof; construct a new one.
    #[wasm_bindgen(getter, js_name = graphReleased)]
    pub fn graph_released(&self) -> bool {
        self.prover.is_none()
    }

    #[wasm_bindgen(js_name = authenticateZkeyChunk)]
    pub fn authenticate_zkey_chunk(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        self.authenticator
            .as_mut()
            .ok_or_else(|| JsError::new(AUTHENTICATION_COMPLETE))?
            .update(bytes)
            .map_err(js_error)
    }

    /// Finish the whole-file authentication pass. On a digest mismatch the
    /// pass restarts: feed the complete zkey again from byte 0.
    #[wasm_bindgen(js_name = finishZkeyAuthentication)]
    pub fn finish_zkey_authentication(&mut self) -> Result<u64, JsError> {
        let authenticator = self
            .authenticator
            .take()
            .ok_or_else(|| JsError::new(AUTHENTICATION_COMPLETE))?;
        match authenticator.finish() {
            Ok(bytes) => {
                self.authenticated = true;
                self.authenticated_bytes = bytes;
                Ok(bytes)
            }
            Err(error) => {
                self.authenticator = Some(self.fresh_authenticator()?);
                Err(JsError::new(&format!(
                    "{error}; zkey authentication restarted, feed the zkey again from byte 0"
                )))
            }
        }
    }

    /// Discard a partial or completed whole-file authentication pass so the
    /// zkey can be authenticated again from byte 0. Refused while a proof is
    /// active; abort it first.
    #[wasm_bindgen(js_name = resetZkeyAuthentication)]
    pub fn reset_zkey_authentication(&mut self) -> Result<(), JsError> {
        if self.proof_active() {
            return Err(JsError::new(
                "cannot reset zkey authentication while a SPARROW proof is active; call abortProof first",
            ));
        }
        self.authenticator = Some(self.fresh_authenticator()?);
        self.authenticated = false;
        self.authenticated_bytes = 0;
        Ok(())
    }

    /// Drop any active framed or manifest-authenticated proof. Idempotent.
    ///
    /// A reusable prover can begin another proof afterwards. A one-shot begin
    /// has already released the SAGE graph, so after aborting it every begin
    /// method reports that release; construct a new prover to retry.
    #[wasm_bindgen(js_name = abortProof)]
    pub fn abort_proof(&mut self) {
        self.proof = None;
        self.manifest_proof = None;
    }

    #[wasm_bindgen(js_name = beginProof)]
    pub fn begin_proof(&mut self, input_json: String) -> Result<(), JsError> {
        let input_json = Zeroizing::new(input_json);
        self.check_can_begin(true)?;
        let assignment = self
            .prover
            .as_ref()
            .ok_or_else(|| JsError::new(GRAPH_RELEASED))?
            .calculate_witness_json(&input_json)
            .map_err(js_error)?;
        self.install_proof(assignment)
    }

    /// Evaluate once and release the compiled SAGE program before the QAP
    /// and MSM phases. Mobile callers that do not reuse a circuit should
    /// prefer this so the graph's instruction storage can be recycled.
    #[wasm_bindgen(js_name = beginOneShotProof)]
    pub fn begin_one_shot_proof(&mut self, input_json: String) -> Result<(), JsError> {
        let input_json = Zeroizing::new(input_json);
        self.check_can_begin(true)?;
        let proof = build_then_release(&mut self.prover, |prover| {
            let assignment = prover.calculate_witness_json(&input_json)?;
            StreamingProofBuilder::new(assignment, &self.expected_zkey_sha256, self.config)
                .map(|proof| proof.with_authenticated_length(self.authenticated_bytes))
        })
        .ok_or_else(|| JsError::new(GRAPH_RELEASED))?
        .map_err(js_error)?;
        self.proof = Some(proof);
        Ok(())
    }

    /// Begin-time preconditions, ordered so a released one-shot graph is
    /// always reported as such rather than as a missing authentication.
    fn check_can_begin(&self, requires_authentication: bool) -> Result<(), JsError> {
        if self.proof_active() {
            return Err(JsError::new(
                "a SPARROW proof is already active; finish it or call abortProof",
            ));
        }
        if self.prover.is_none() {
            return Err(JsError::new(GRAPH_RELEASED));
        }
        if requires_authentication && !self.authenticated {
            return Err(JsError::new(
                "authenticate the zkey before beginning a proof",
            ));
        }
        Ok(())
    }

    fn fresh_authenticator(&self) -> Result<StreamingAuthenticator, JsError> {
        StreamingAuthenticator::new(&self.expected_zkey_sha256).map_err(js_error)
    }

    fn install_proof(&mut self, assignment: Vec<Fr>) -> Result<(), JsError> {
        self.proof = Some(
            StreamingProofBuilder::new(assignment, &self.expected_zkey_sha256, self.config)
                .map_err(js_error)?
                .with_authenticated_length(self.authenticated_bytes),
        );
        Ok(())
    }

    /// Begin a one-pass proof. The small chunk manifest is authenticated
    /// up front; each zkey chunk is then checked before parsing.
    #[wasm_bindgen(js_name = beginOneShotManifestProof)]
    pub fn begin_one_shot_manifest_proof(
        &mut self,
        input_json: String,
        manifest_bytes: &[u8],
        expected_manifest_sha256: &str,
    ) -> Result<(), JsError> {
        let input_json = Zeroizing::new(input_json);
        self.check_can_begin(false)?;
        let manifest = ZkeyChunkManifest::from_bytes(
            manifest_bytes,
            expected_manifest_sha256,
            &self.expected_zkey_sha256,
        )
        .map_err(js_error)?;
        let manifest_proof = build_then_release(&mut self.prover, |prover| {
            let assignment = prover.calculate_witness_json(&input_json)?;
            ManifestProofStream::new(assignment, manifest, self.config)
        })
        .ok_or_else(|| JsError::new(GRAPH_RELEASED))?
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
fn proof_mut(prover: &mut WasmStreamingProver) -> Result<&mut StreamingProofBuilder, JsError> {
    prover
        .proof
        .as_mut()
        .ok_or_else(|| JsError::new("no SPARROW proof is active"))
}

#[cfg(feature = "sparrow")]
const GRAPH_RELEASED: &str =
    "the one-shot SAGE graph has already been released; construct a new WasmStreamingProver";

#[cfg(feature = "sparrow")]
const AUTHENTICATION_COMPLETE: &str = "zkey authentication pass is already complete; call resetZkeyAuthentication to authenticate again";

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
