#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
//!
//! ## Security model
//!
//! The proving key parser is the committed `rs-core` implementation vendored
//! from `ark-circom` without its Wasmer witness calculator. Bulk query points are
//! constructed unchecked for fast startup, so every caller must provide a pinned
//! SHA-256 digest for the zkey. Whole-key native loads authenticate before parsing;
//! seekable readers also authenticate every buffered chunk before exposing it
//! to the parser, so concurrent writes cannot substitute bytes after hashing.
//! The prototype forward parser now uses the same authenticated chunk view.
//! One-pass manifest loads authenticate each chunk before parsing. The browser
//! two-response adapter records private chunk hashes during authentication and
//! checks each second-response chunk before exposing its bytes to the parser.
//!
//! ### Where a pin must come from
//!
//! Every check here reduces to the digests the caller supplies, so those values
//! are the trust boundary. A pin fetched from the same place as the artifact it
//! describes proves nothing: an attacker who controls that host serves a
//! matched pair and every check in this crate passes. Pins must be compiled
//! into the application, or read from something the artifact host does not
//! control - the deployed verifier contract being the natural source.
//!
//! On the one-pass manifest paths (`zkey-manifest`), the manifest pin is the
//! sole trust root. `ZkeyChunkManifest::from_bytes` authenticates the manifest
//! against it, and every zkey chunk is then checked against the manifest's
//! chunk table before parsing. The zkey pin passed alongside it is only a
//! consistency check: it is compared with the whole-file digest the manifest
//! *claims*, and that digest is not recomputed while loading or proving -
//! avoiding that second pass is the manifest's purpose. Only
//! `ZkeyChunkManifest::verify_reader` recomputes it, so release tooling must
//! run it before publishing a manifest pin.
//!
//! [`Prover::verifying_key_digest`] exists to make that practical. It is 32
//! bytes and stable across artifact rebuilds, so it can live in application
//! code or be derived from the verifier contract, while the zkey digest - which
//! moves whenever the artifact is re-attested or recompressed - can be fetched.
//! A substituted key from a foreign setup then fails the verifying-key
//! comparison even when its own pin is consistent.
//!
//! Note that an attacker able to change a pin can usually change the code that
//! reads it, and code that computes the witness can exfiltrate it directly. The
//! artifact-substitution paths below therefore matter most where artifacts are
//! distributed separately from the application. The witness graph deserves the
//! same care as the proving key: public signals are taken straight from the
//! assignment the graph produces, so a substituted graph can place a secret in
//! a published signal, and no proof needs to verify for that to leak.
//!
//! Pinning fixes *which* artifact is used, not whether that artifact is well
//! formed. A crafted CRS can keep proofs verifying while leaking witness data
//! through them, and valid curve points are not evidence against that. Release
//! tooling should therefore gate a pin on [`zkey::validate_proving_key`] plus
//! [`zkey::validate_crs_consistency`], and on `snarkjs zkey verify` against the
//! ceremony PTAU and the circuit's R1CS - see `examples/artifact_manifest_check`.
//!
//! Every build uses Curvy's ark-groth16 0.6-compatible proof assembly and its
//! batch-affine MSM. Native builds enable `std` and prove on one thread by
//! default; the opt-in `parallel` feature schedules the same proof on the
//! host's global Rayon pool. Portable WASM uses the `wasm` feature; threaded
//! browser builds use `wasm-threads` and export `initThreadPool(n)` so the host
//! selects the worker count explicitly. The prototype `compact-matrix` feature
//! keeps CSR constraints, which never need conversion to arkworks' nested
//! matrix type.

pub mod artifacts;
#[doc(hidden)]
pub mod phase_timing;
#[cfg(all(feature = "bench", feature = "parallel"))]
pub mod proof_bench;
pub mod qap;
#[cfg(all(
    feature = "wasm-simd-fft",
    target_arch = "wasm32",
    target_feature = "simd128"
))]
mod simd_fft;
#[cfg(feature = "scratch")]
mod workspace;
#[cfg(feature = "scratch")]
pub use workspace::ProofWorkspace;
#[cfg(feature = "sparrow")]
pub mod sparrow;
#[cfg(feature = "sparrow")]
pub use sparrow::{
    StreamingAuthenticator, StreamingConfig, StreamingError, StreamingProofBuilder, StreamingProver,
};
pub mod wtns;
pub mod zkey;

mod authenticated_reader;
mod groth16_prover;
mod msm;
#[cfg(all(
    feature = "wasm-simd-msm",
    target_arch = "wasm32",
    target_feature = "simd128"
))]
mod msm_simd;

use std::io::{Cursor, Read, Seek};

use phase_timing::phase;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{
    Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey, prepare_verifying_key,
};
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::SerializationError;
use curvy_witness::{WitnessError, WitnessGraph};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use thiserror::Error;

use wtns::WtnsError;
use zkey::ZkeyMatrices;

/// Stable developer-facing execution modes for the two proving architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProverMode {
    /// Keep the authenticated proving key and matrices in memory for reuse.
    Resident,
    /// Process the authenticated proving key incrementally with bounded memory.
    Streaming,
}

impl ProverMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resident => "resident",
            Self::Streaming => "streaming",
        }
    }

    pub const fn profile(self) -> &'static str {
        match self {
            Self::Resident => HAWK_PROFILE,
            Self::Streaming => SPARROW_PROFILE,
        }
    }
}

impl std::fmt::Display for ProverMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// HAWK: High-throughput Authenticated Whole-Key prover.
pub const HAWK_PROFILE: &str = "HAWK";

/// SPARROW: Streaming Prover Architecture for Resource-Restricted One-pass Workflows.
pub const SPARROW_PROFILE: &str = "SPARROW";

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("expected zkey SHA-256 must be exactly 64 hexadecimal characters")]
    InvalidExpectedHash,
    #[error("zkey SHA-256 mismatch: expected {expected}, got {actual}")]
    ZkeyHashMismatch { expected: String, actual: String },
    #[error("failed to read zkey: {0}")]
    ZkeyIo(#[from] std::io::Error),
    #[error("invalid zkey: {0}")]
    InvalidZkey(SerializationError),
    #[error(transparent)]
    InvalidWitness(#[from] WtnsError),
    #[error(transparent)]
    InvalidWitnessGraph(#[from] WitnessError),
    #[error("witness assignment length mismatch: expected {expected}, got {actual}")]
    AssignmentLength { expected: usize, actual: usize },
    #[error("witness assignment must start with the constant one signal")]
    AssignmentConstant,
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
        phase!("load.sha256", verify_sha256(bytes, expected_sha256))?;
        let mut cursor = Cursor::new(bytes);
        Self::from_authenticated_zkey_reader(&mut cursor)
    }

    /// Authenticate and parse a seekable zkey without retaining the complete
    /// artifact in memory.
    ///
    /// By default, the reader is rewound and hashed to EOF while recording a
    /// digest for each 64 KiB chunk. Once the whole-artifact pin matches, every
    /// parser read is served from a private chunk buffer checked against those
    /// digests. This also authenticates rereads after seeks, so a backing store
    /// rewritten during parsing cannot substitute bytes. Besides the parsed
    /// key and point conversion buffer, this retains 64 KiB plus 32 bytes per
    /// chunk, rather than a full artifact snapshot.
    ///
    /// The `zkey-single-pass` feature instead parses the artifact in one forward
    /// walk over the same authenticated chunk view. It no longer permits
    /// parsing or artifact-sized allocations before the whole pin matches.
    pub fn from_zkey_reader<R: Read + Seek>(
        reader: &mut R,
        expected_sha256: &str,
    ) -> Result<Self, ProverError> {
        #[cfg(feature = "zkey-single-pass")]
        {
            let mut authenticated =
                authenticated_reader::AuthenticatedReader::new(reader, expected_sha256)?;
            let (pk, matrices, digest) =
                zkey::read_zkey_sequential(&mut authenticated).map_err(ProverError::InvalidZkey)?;
            // Nothing parsed above has been handed to a caller yet, so a
            // mismatch here drops the key material entirely.
            verify_digest(digest, expected_sha256)?;
            zkey::spot_check(&pk).map_err(ProverError::InvalidZkey)?;
            Ok(Self::from_parsed(pk, matrices))
        }
        #[cfg(not(feature = "zkey-single-pass"))]
        {
            let mut authenticated =
                authenticated_reader::AuthenticatedReader::new(reader, expected_sha256)?;
            Self::from_authenticated_zkey_reader(&mut authenticated)
        }
    }

    fn from_authenticated_zkey_reader<R: Read + Seek>(reader: &mut R) -> Result<Self, ProverError> {
        let (pk, matrices) = zkey::read_zkey(reader).map_err(ProverError::InvalidZkey)?;
        Ok(Self::from_parsed(pk, matrices))
    }

    /// Load a resident key in one forward pass using an independently pinned
    /// manifest. Each chunk authenticates against the manifest before point
    /// decoding. The manifest pin is the trust root here: the zkey pin given to
    /// [`artifacts::manifest::ZkeyChunkManifest::from_bytes`] is only compared
    /// with the digest the manifest claims, which this load does not recompute.
    /// Release tooling must check that claim with
    /// [`artifacts::manifest::ZkeyChunkManifest::verify_reader`] before
    /// publishing the manifest pin.
    ///
    /// The source starts at byte zero and does not need Seek. As with the
    /// sequential parser, the Groth16 header must precede the query sections.
    #[cfg(feature = "zkey-manifest")]
    pub fn from_zkey_manifest_reader<R: Read>(
        reader: &mut R,
        manifest: &artifacts::manifest::ZkeyChunkManifest,
    ) -> Result<Self, artifacts::manifest::ArtifactError> {
        use artifacts::manifest::ArtifactError;

        let mut authenticated = artifacts::manifest::ManifestReader::new(reader, manifest);
        // The manifest reader reports a changed chunk as an `io::Error` wrapping
        // its typed error; surface that rather than a generic I/O failure.
        let parsed = zkey::read_zkey_forward(&mut authenticated, manifest.zkey_bytes(), false);
        let (pk, matrices, _) = parsed.map_err(|error| match error {
            SerializationError::IoError(error) => error
                .downcast::<ArtifactError>()
                .unwrap_or_else(ArtifactError::Io),
            error => ArtifactError::InvalidZkey(error.to_string()),
        })?;
        authenticated.finish()?;
        zkey::spot_check(&pk).map_err(|error| ArtifactError::InvalidZkey(error.to_string()))?;
        Ok(Self::from_parsed(pk, matrices))
    }

    fn from_parsed(pk: ProvingKey<Bn254>, matrices: ZkeyMatrices<Fr>) -> Self {
        let pvk = phase!("load.prepare_vk", prepare_verifying_key(&pk.vk));
        let assignment_size = pk.a_query.len();
        Self {
            pk,
            matrices,
            pvk,
            assignment_size,
        }
    }

    pub fn num_constraints(&self) -> usize {
        self.matrices.num_constraints
    }

    pub fn num_public(&self) -> usize {
        self.matrices.num_instance_variables.saturating_sub(1)
    }

    /// SHA-256 over this key's verifying key, as 64 lowercase hex characters.
    ///
    /// The zkey digest pins the artifact; this pins the thing a verifier
    /// actually encodes. Self-verification cannot make that distinction,
    /// because the verifying key it uses comes from the same artifact - so a
    /// zkey from a different setup, carried with its own matching pin, passes
    /// every other check in this crate. Compare this against a constant taken
    /// from the deployed verifier to reject that case:
    ///
    /// ```ignore
    /// if prover.verifying_key_digest() != DEPLOYED_VERIFIER_VK {
    ///     return Err(/* wrong circuit or wrong ceremony */);
    /// }
    /// ```
    ///
    /// It is also stable across artifact churn: rebuilding a zkey with a new
    /// contributions section changes the zkey digest but not this one.
    ///
    /// The exact bytes hashed are documented on the private
    /// `verifying_key_digest` helper in this module, and are stable by design:
    /// the encoding is defined here rather than delegated to a dependency.
    pub fn verifying_key_digest(&self) -> String {
        hex(&verifying_key_digest(&self.pk.vk))
    }

    /// Exact retained constraint-array payload for benchmark instrumentation.
    #[cfg(feature = "bench")]
    #[doc(hidden)]
    pub fn matrix_storage_bytes(&self) -> usize {
        self.matrices.storage_bytes()
    }

    /// Generate a proof without verifying it. Use [`Self::prove_assignment`] to
    /// reject unsatisfied witnesses before returning a proof bundle.
    pub fn prove(&self, full_assignment: &[Fr]) -> Result<Proof<Bn254>, ProverError> {
        self.validate_assignment(full_assignment)?;
        let mut rng = ark_std::rand::rngs::OsRng;
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        #[cfg(feature = "compact-matrix")]
        let proof = groth16_prover::create_proof_with_compact_matrices(
            &self.pk,
            r,
            s,
            &self.matrices.matrices,
            self.matrices.num_instance_variables,
            self.matrices.num_constraints,
            full_assignment,
        );

        #[cfg(not(feature = "compact-matrix"))]
        let proof = groth16_prover::create_proof_with_matrices(
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

    /// Experimental buffer reuse. A mutable workspace cannot serve concurrent proofs.
    #[cfg(feature = "scratch")]
    pub fn prove_with_workspace(
        &self,
        full_assignment: &[Fr],
        workspace: &mut ProofWorkspace,
    ) -> Result<Proof<Bn254>, ProverError> {
        let lease = workspace::Lease(workspace);
        self.validate_assignment(full_assignment)?;
        let mut rng = ark_std::rand::rngs::OsRng;
        groth16_prover::create_proof_with_workspace(
            self,
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            full_assignment,
            lease.0,
        )
        .map_err(ProverError::ProofGeneration)
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
        let assignment = zeroize::Zeroizing::new(wtns::read_wtns(bytes)?);
        self.prove_assignment(&assignment)
    }

    /// Prove and self-verify one direct arkworks witness assignment.
    pub fn prove_assignment(&self, assignment: &[Fr]) -> Result<ProofBundle, ProverError> {
        let proof = phase!("proof.prove", self.prove(assignment))?;
        let public_inputs = self.public_inputs(assignment)?;
        if !phase!("proof.verify", self.verify(&proof, public_inputs))? {
            return Err(ProverError::SelfVerificationFailed);
        }
        Ok(phase!(
            "proof.json",
            ProofBundle {
                proof_json: proof_to_snarkjs_json(&proof),
                public_signals_json: publics_to_json(public_inputs),
            }
        ))
    }

    fn validate_assignment(&self, full_assignment: &[Fr]) -> Result<(), ProverError> {
        self.validate_assignment_size(full_assignment.len())?;
        if full_assignment.first() != Some(&Fr::from(1)) {
            return Err(ProverError::AssignmentConstant);
        }
        Ok(())
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

/// HAWK resident prover: an authenticated graph and fully loaded proving key.
pub struct ResidentProver {
    prover: Prover,
    witness_graph: ResidentWitness,
}

enum ResidentWitness {
    Graph(WitnessGraph),
    #[cfg(feature = "sage")]
    Sage(curvy_witness::sage::SageGraph),
}

impl ResidentProver {
    pub const MODE: ProverMode = ProverMode::Resident;
    pub const PROFILE: &'static str = HAWK_PROFILE;

    /// Combine independently authenticated key and graph artifacts. Dimensions
    /// are checked before this reusable prover is returned.
    pub fn with_graph(prover: Prover, graph: WitnessGraph) -> Result<Self, ProverError> {
        prover.validate_assignment_size(graph.assignment_size())?;
        Ok(Self {
            prover,
            witness_graph: ResidentWitness::Graph(graph),
        })
    }

    /// Use SAGE's live-value slots with a resident proving key.
    #[cfg(feature = "sage")]
    pub fn with_sage(
        prover: Prover,
        graph: curvy_witness::sage::SageGraph,
    ) -> Result<Self, ProverError> {
        prover.validate_assignment_size(graph.assignment_size())?;
        Ok(Self {
            prover,
            witness_graph: ResidentWitness::Sage(graph),
        })
    }

    /// Load an authenticated compiled SAGE program, binding it to the expected
    /// source graph. This avoids compiling the graph at every process start.
    #[cfg(feature = "sage")]
    pub fn from_compiled_sage(
        prover: Prover,
        program: &[u8],
        expected_program_sha256: &str,
        expected_graph_sha256: &str,
        limits: curvy_witness::Limits,
    ) -> Result<Self, ProverError> {
        let graph = curvy_witness::sage::SageGraph::from_compiled_bytes_with_limits(
            program,
            expected_program_sha256,
            expected_graph_sha256,
            limits,
        )?;
        Self::with_sage(prover, graph)
    }

    pub fn witness_backend(&self) -> &'static str {
        match &self.witness_graph {
            ResidentWitness::Graph(_) => "graph",
            #[cfg(feature = "sage")]
            ResidentWitness::Sage(_) => "sage",
        }
    }

    pub const fn mode(&self) -> ProverMode {
        Self::MODE
    }

    pub const fn profile(&self) -> &'static str {
        Self::PROFILE
    }

    /// SHA-256 over the loaded key's verifying key. See
    /// [`Prover::verifying_key_digest`].
    pub fn verifying_key_digest(&self) -> String {
        self.prover.verifying_key_digest()
    }

    pub fn from_artifacts(
        zkey: &[u8],
        expected_zkey_sha256: &str,
        witness_graph: &[u8],
        expected_graph_sha256: &str,
    ) -> Result<Self, ProverError> {
        Self::from_artifacts_with_limits(
            zkey,
            expected_zkey_sha256,
            witness_graph,
            expected_graph_sha256,
            curvy_witness::Limits::client(),
        )
    }

    /// Construct with an explicit witness-graph resource budget.
    ///
    /// Keep client-facing callers on [`Self::from_artifacts`]. Native batch
    /// provers that deliberately accept larger circuit profiles can opt into
    /// [`curvy_witness::Limits::batch_prover`] here.
    pub fn from_artifacts_with_limits(
        zkey: &[u8],
        expected_zkey_sha256: &str,
        witness_graph: &[u8],
        expected_graph_sha256: &str,
        limits: curvy_witness::Limits,
    ) -> Result<Self, ProverError> {
        let prover = phase!(
            "load.zkey",
            Prover::from_zkey_bytes(zkey, expected_zkey_sha256)
        )?;
        let witness_graph = phase!(
            "load.graph",
            WitnessGraph::from_bytes_with_limits(witness_graph, expected_graph_sha256, limits)
        )?;
        Self::with_graph(prover, witness_graph)
    }

    /// Construct from a seekable zkey source and an in-memory witness graph.
    /// This is the native file-backed counterpart to [`Self::from_artifacts`].
    pub fn from_artifacts_reader<R: Read + Seek>(
        zkey: &mut R,
        expected_zkey_sha256: &str,
        witness_graph: &[u8],
        expected_graph_sha256: &str,
    ) -> Result<Self, ProverError> {
        Self::from_artifacts_reader_with_limits(
            zkey,
            expected_zkey_sha256,
            witness_graph,
            expected_graph_sha256,
            curvy_witness::Limits::client(),
        )
    }

    /// Seekable-reader counterpart to [`Self::from_artifacts_with_limits`].
    pub fn from_artifacts_reader_with_limits<R: Read + Seek>(
        zkey: &mut R,
        expected_zkey_sha256: &str,
        witness_graph: &[u8],
        expected_graph_sha256: &str,
        limits: curvy_witness::Limits,
    ) -> Result<Self, ProverError> {
        let prover = Prover::from_zkey_reader(zkey, expected_zkey_sha256)?;
        let witness_graph =
            WitnessGraph::from_bytes_with_limits(witness_graph, expected_graph_sha256, limits)?;
        Self::with_graph(prover, witness_graph)
    }

    pub fn num_constraints(&self) -> usize {
        self.prover.num_constraints()
    }

    pub fn num_public(&self) -> usize {
        self.prover.num_public()
    }

    pub fn r1cs_sha256(&self) -> [u8; 32] {
        match &self.witness_graph {
            ResidentWitness::Graph(graph) => graph.r1cs_sha256(),
            #[cfg(feature = "sage")]
            ResidentWitness::Sage(graph) => graph.r1cs_sha256(),
        }
    }

    /// Exact retained constraint-array payload for benchmark instrumentation.
    #[cfg(feature = "bench")]
    #[doc(hidden)]
    pub fn matrix_storage_bytes(&self) -> usize {
        self.prover.matrix_storage_bytes()
    }

    /// Evaluate authenticated `curvy-graph-v1` inputs without proving yet.
    ///
    /// This split is useful to native operators that report witness and proof
    /// timings separately. Most callers should use [`Self::prove_json`].
    pub fn calculate_witness_json(&self, input_json: &str) -> Result<Vec<Fr>, ProverError> {
        Ok(match &self.witness_graph {
            ResidentWitness::Graph(graph) => graph.calculate_json(input_json)?,
            #[cfg(feature = "sage")]
            ResidentWitness::Sage(graph) => graph.calculate_json(input_json)?,
        })
    }

    /// Prove and self-verify an assignment produced by this circuit's graph.
    pub fn prove_assignment(&self, assignment: &[Fr]) -> Result<ProofBundle, ProverError> {
        self.prover.prove_assignment(assignment)
    }

    /// Optional bounded witness, FFT, and MSM-scalar reuse, with self-verification.
    #[cfg(feature = "scratch")]
    pub fn prove_json_with_workspace(
        &self,
        input_json: &str,
        witness: &mut curvy_witness::WitnessWorkspace,
        proof: &mut ProofWorkspace,
    ) -> Result<ProofBundle, ProverError> {
        let consume = |assignment: &[Fr]| {
            let generated = self.prover.prove_with_workspace(assignment, proof)?;
            let publics = self.prover.public_inputs(assignment)?;
            if !self.prover.verify(&generated, publics)? {
                return Err(ProverError::SelfVerificationFailed);
            }
            Ok(ProofBundle {
                proof_json: proof_to_snarkjs_json(&generated),
                public_signals_json: publics_to_json(publics),
            })
        };
        match &self.witness_graph {
            ResidentWitness::Graph(graph) => {
                graph.with_witness_json(input_json, witness, consume)?
            }
            #[cfg(feature = "sage")]
            ResidentWitness::Sage(graph) => {
                graph.with_witness_json(input_json, witness, consume)?
            }
        }
    }

    pub fn prove_json(&self, input_json: &str) -> Result<ProofBundle, ProverError> {
        let assignment = zeroize::Zeroizing::new(phase!(
            "proof.witness",
            self.calculate_witness_json(input_json)
        )?);
        self.prove_assignment(&assignment)
    }
}

pub struct ProofBundle {
    pub proof_json: String,
    pub public_signals_json: String,
}

fn verify_sha256(bytes: &[u8], expected_sha256: &str) -> Result<(), ProverError> {
    // Many 1 MiB updates, not one call over the whole artifact: V8 runs a WASM
    // call to completion in the tier it started in, so a single digest of a
    // freshly loaded module hashed 90-230 MB zkeys in baseline code, 6x slower
    // (benchmarks 6.11).
    let mut hasher = Sha256::new();
    for chunk in bytes.chunks(1 << 20) {
        hasher.update(chunk);
    }
    verify_digest(hasher.finalize().into(), expected_sha256)
}

/// SHA-256 over a Groth16 verifying key, in an encoding this crate defines.
///
/// Deliberately not `CanonicalSerialize`: a pinned digest must not move when a
/// dependency changes its wire format. The bytes hashed are, in order:
///
/// - the 8-byte domain tag `CVYVK\0\0\0` (tag plus format version);
/// - `alpha_g1`, then `beta_g2`, `gamma_g2`, `delta_g2`;
/// - the `gamma_abc_g1` length as a little-endian `u32`, then its points.
///
/// A G1 point is `x` then `y`; a G2 point is `x.c0, x.c1, y.c0, y.c1`. Every
/// coordinate is the canonical integer in 32 big-endian bytes - the same value
/// snarkjs prints in decimal - and the point at infinity is all zeroes.
fn verifying_key_digest(vk: &VerifyingKey<Bn254>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CVYVK\0\0\0");
    digest.update(encode_g1(&vk.alpha_g1));
    digest.update(encode_g2(&vk.beta_g2));
    digest.update(encode_g2(&vk.gamma_g2));
    digest.update(encode_g2(&vk.delta_g2));
    digest.update(
        u32::try_from(vk.gamma_abc_g1.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for point in &vk.gamma_abc_g1 {
        digest.update(encode_g1(point));
    }
    digest.finalize().into()
}

fn encode_fq(value: &Fq, out: &mut [u8]) {
    out.copy_from_slice(&value.into_bigint().to_bytes_be());
}

fn encode_g1(point: &G1Affine) -> [u8; 64] {
    let mut encoded = [0_u8; 64];
    if let Some((x, y)) = point.xy() {
        encode_fq(&x, &mut encoded[..32]);
        encode_fq(&y, &mut encoded[32..]);
    }
    encoded
}

fn encode_g2(point: &G2Affine) -> [u8; 128] {
    let mut encoded = [0_u8; 128];
    if let Some((x, y)) = point.xy() {
        encode_fq(&x.c0, &mut encoded[..32]);
        encode_fq(&x.c1, &mut encoded[32..64]);
        encode_fq(&y.c0, &mut encoded[64..96]);
        encode_fq(&y.c1, &mut encoded[96..]);
    }
    encoded
}

fn verify_digest(actual: [u8; 32], expected_sha256: &str) -> Result<(), ProverError> {
    let expected_bytes = decode_sha256(expected_sha256)?;
    if actual != expected_bytes {
        return Err(ProverError::ZkeyHashMismatch {
            expected: hex(&expected_bytes),
            actual: hex(&actual),
        });
    }
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ProverError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProverError::InvalidExpectedHash);
    }
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ProverError::InvalidExpectedHash)?;
    }
    Ok(decoded)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
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
    let g1 = |point: &G1Affine| {
        if point.is_zero() {
            "[\"0\",\"1\",\"0\"]".to_string()
        } else {
            format!("[\"{}\",\"{}\",\"1\"]", fq_dec(&point.x), fq_dec(&point.y))
        }
    };
    let b = if proof.b.is_zero() {
        "[[\"0\",\"0\"],[\"1\",\"0\"],[\"0\",\"0\"]]".to_string()
    } else {
        format!(
            "[{}, {},[\"1\",\"0\"]]",
            fq2_json(&proof.b.x),
            fq2_json(&proof.b.y)
        )
    };
    format!(
        "{{\"pi_a\":{},\"pi_b\":{},\"pi_c\":{},\"protocol\":\"groth16\",\"curve\":\"bn128\"}}",
        g1(&proof.a),
        b,
        g1(&proof.c),
    )
}

pub fn publics_to_json(publics: &[Fr]) -> String {
    let items = publics
        .iter()
        .map(|public| format!("\"{}\"", fr_dec(public)))
        .collect::<Vec<_>>();
    format!("[{}]", items.join(","))
}

/// Pack a witness assignment as concatenated canonical 32-byte big-endian
/// BN254 scalar-field elements.
pub fn assignment_to_packed_be(assignment: &[Fr]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(assignment.len().saturating_mul(32));
    for scalar in assignment {
        let bigint = scalar.into_bigint();
        for limb in bigint.as_ref().iter().rev() {
            packed.extend_from_slice(&limb.to_be_bytes());
        }
    }
    packed
}

#[cfg(feature = "wasm-threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(feature = "wasm")]
mod wasm_api;

#[cfg(test)]
mod tests {
    #[test]
    fn identity_proof_elements_use_snarkjs_projective_zero() {
        let proof = ark_groth16::Proof::<ark_bn254::Bn254>::default();
        let encoded: serde_json::Value =
            serde_json::from_str(&super::proof_to_snarkjs_json(&proof)).unwrap();
        assert_eq!(encoded["pi_a"], serde_json::json!(["0", "1", "0"]));
        assert_eq!(encoded["pi_c"], encoded["pi_a"]);
        assert_eq!(
            encoded["pi_b"],
            serde_json::json!([["0", "0"], ["1", "0"], ["0", "0"]])
        );
    }

    use std::io::{Cursor, Read, Seek, SeekFrom};

    use sha2::{Digest, Sha256};

    use super::{Prover, ProverError, verify_sha256};
    use ark_serialize::SerializationError;

    const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");

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

    /// Every field a Groth16 verifier encodes must reach the digest, including
    /// the length and the order of the input commitments.
    #[test]
    fn verifying_key_digest_covers_every_verifier_field() {
        let expected = Sha256::digest(ZKEY)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let prover = Prover::from_zkey_bytes(ZKEY, &expected).expect("fixture zkey");
        let vk = &prover.pk.vk;
        let base = super::verifying_key_digest(vk);

        let mut alpha = vk.clone();
        alpha.alpha_g1 = -alpha.alpha_g1;
        let mut beta = vk.clone();
        beta.beta_g2 = -beta.beta_g2;
        let mut gamma = vk.clone();
        gamma.gamma_g2 = -gamma.gamma_g2;
        let mut delta = vk.clone();
        delta.delta_g2 = -delta.delta_g2;
        let mut longer = vk.clone();
        longer.gamma_abc_g1.push(longer.gamma_abc_g1[0]);
        let mut reordered = vk.clone();
        reordered.gamma_abc_g1.swap(0, 1);

        for (label, mutated) in [
            ("alpha_g1", alpha),
            ("beta_g2", beta),
            ("gamma_g2", gamma),
            ("delta_g2", delta),
            ("gamma_abc_g1 length", longer),
            ("gamma_abc_g1 order", reordered),
        ] {
            assert_ne!(
                super::verifying_key_digest(&mutated),
                base,
                "{label} must reach the verifying-key digest",
            );
        }

        // Stable across repeated loads of the same artifact.
        let again = Prover::from_zkey_bytes(ZKEY, &expected).expect("fixture zkey");
        assert_eq!(super::verifying_key_digest(&again.pk.vk), base);
    }

    #[test]
    fn seekable_reader_authenticates_then_parses_the_same_zkey() {
        let digest = Sha256::digest(ZKEY)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let prover = Prover::from_zkey_reader(&mut Cursor::new(ZKEY), &digest)
            .expect("fixture reader must parse");
        assert_eq!(prover.num_constraints(), 1);
        assert_eq!(prover.num_public(), 1);
    }

    /// A backing store that serves one artifact for its first `switch_after`
    /// delivered bytes and a different one after that. This is the shape of a
    /// file rewritten while a reader is still consuming it.
    struct MutatingReader {
        first: Vec<u8>,
        second: Vec<u8>,
        switch_after: u64,
        delivered: u64,
        position: u64,
    }

    impl MutatingReader {
        fn source(&self) -> &[u8] {
            if self.delivered >= self.switch_after {
                &self.second
            } else {
                &self.first
            }
        }
    }

    impl Read for MutatingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let start = usize::try_from(self.position).expect("fixture offsets fit in usize");
            let source = self.source();
            let count = source.len().saturating_sub(start).min(buffer.len());
            buffer[..count].copy_from_slice(&source[start..start + count]);
            self.position += count as u64;
            self.delivered += count as u64;
            Ok(count)
        }
    }

    impl Seek for MutatingReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            let length = self.source().len() as u64;
            self.position = match position {
                SeekFrom::Start(offset) => offset,
                SeekFrom::End(offset) => length.saturating_add_signed(offset),
                SeekFrom::Current(offset) => self.position.saturating_add_signed(offset),
            };
            Ok(self.position)
        }
    }

    #[test]
    fn seekable_reader_rejects_a_zkey_that_changes_under_the_parser() {
        let digest = Sha256::digest(ZKEY)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        // Swap after the authentication pass. The default reader must reject
        // the changed chunk before exposing any of it to the parser.
        let (switch_after, second) = {
            let mut swapped = ZKEY.to_vec();
            let last = swapped.len() - 1;
            swapped[last] ^= 0xff;
            (ZKEY.len() as u64, swapped)
        };

        let mut reader = MutatingReader {
            first: ZKEY.to_vec(),
            second,
            switch_after,
            delivered: 0,
            position: 0,
        };
        let error = Prover::from_zkey_reader(&mut reader, &digest)
            .err()
            .expect("a zkey that changed under the parser must be rejected");
        assert!(matches!(
            error,
            ProverError::InvalidZkey(SerializationError::IoError(_))
        ));
    }

    /// Serves the trusted bytes to bulk hash passes, but a different valid key
    /// to smaller parser reads. Hashing before and after parsing accepts this
    /// reader; checking the bytes actually exposed to the parser must reject it.
    struct ParseOnlyMutatingReader {
        changed: Vec<u8>,
        position: u64,
    }

    impl Read for ParseOnlyMutatingReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let source = if output.len() >= 64 * 1024 {
                ZKEY
            } else {
                &self.changed
            };
            let mut cursor = Cursor::new(source);
            cursor.set_position(self.position);
            let count = cursor.read(output)?;
            self.position = cursor.position();
            Ok(count)
        }
    }

    impl Seek for ParseOnlyMutatingReader {
        fn seek(&mut self, target: SeekFrom) -> std::io::Result<u64> {
            let mut cursor = Cursor::new(ZKEY);
            cursor.set_position(self.position);
            self.position = cursor.seek(target)?;
            Ok(self.position)
        }
    }

    #[test]
    fn seekable_reader_rejects_a_transient_valid_key_substitution() {
        let mut changed = ZKEY.to_vec();
        let mut offset = 12;
        loop {
            let id = u32::from_le_bytes(ZKEY[offset..offset + 4].try_into().unwrap());
            let length =
                u64::from_le_bytes(ZKEY[offset + 4..offset + 12].try_into().unwrap()) as usize;
            offset += 12;
            if id == 2 {
                // Replace alpha1 with the distinct, valid beta1 point.
                changed[offset + 84..offset + 148]
                    .copy_from_slice(&ZKEY[offset + 148..offset + 212]);
                break;
            }
            offset += length;
        }
        let digest = |bytes: &[u8]| {
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let expected = digest(ZKEY);
        let trusted = Prover::from_zkey_bytes(ZKEY, &expected).unwrap();
        let substituted = Prover::from_zkey_bytes(&changed, &digest(&changed)).unwrap();
        assert_ne!(
            trusted.verifying_key_digest(),
            substituted.verifying_key_digest()
        );
        let mut reader = ParseOnlyMutatingReader {
            changed,
            position: 0,
        };
        assert!(Prover::from_zkey_reader(&mut reader, &expected).is_err());
    }

    /// Re-emit the fixture with its sections in a different order.
    #[cfg(feature = "zkey-single-pass")]
    fn reordered_zkey(reorder: impl Fn(&mut Vec<(u32, Vec<u8>)>)) -> Vec<u8> {
        let count = u32::from_le_bytes(ZKEY[8..12].try_into().expect("section count"));
        let mut sections = Vec::new();
        let mut offset = 12;
        for _ in 0..count {
            let id = u32::from_le_bytes(ZKEY[offset..offset + 4].try_into().expect("section id"));
            let length = u64::from_le_bytes(
                ZKEY[offset + 4..offset + 12]
                    .try_into()
                    .expect("section length"),
            ) as usize;
            let start = offset + 12;
            sections.push((id, ZKEY[start..start + length].to_vec()));
            offset = start + length;
        }
        reorder(&mut sections);

        let mut out = ZKEY[..12].to_vec();
        for (id, body) in sections {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&(body.len() as u64).to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    /// The fixture's sections are not in ascending id order (1, 2, 4, 3, 9, 8,
    /// 5, 6, 7, 10), so the streaming walk must not assume they are. What it
    /// does need is the Groth header before the queries it sizes.
    #[cfg(feature = "zkey-single-pass")]
    #[test]
    fn streaming_reader_refuses_a_zkey_whose_header_follows_its_queries() {
        let bytes = reordered_zkey(|sections| {
            let header = sections
                .iter()
                .position(|(id, _)| *id == 2)
                .expect("fixture has a Groth header");
            let entry = sections.remove(header);
            sections.push(entry);
        });
        let digest = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let error = Prover::from_zkey_reader(&mut Cursor::new(bytes), &digest)
            .err()
            .expect("a query cannot be sized before its header has been read");
        assert!(matches!(error, ProverError::InvalidZkey(_)));
    }
}
