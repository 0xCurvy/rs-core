//! SPARROW (Streaming Prover Architecture for Resource-Restricted One-pass
//! Workflows), Curvy's bounded-memory Groth16 prover over a sequential snarkjs
//! zkey. The developer-facing entry point is [`StreamingProver`].
//!
//! The preferred protocol authenticates a small pinned manifest first, then
//! authenticates each zkey chunk before feeding it to the parser in a single
//! pass. A compatible whole-file-digest protocol authenticates and rewinds the
//! zkey and rechecks each chunk before exposing it during the proof pass. Constraint coefficients are
//! evaluated as they arrive and every query is reduced into persistent
//! Pippenger buckets, so no zkey section and no vector of query points is
//! retained.

pub mod manifest;
#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod phase_bench;
#[cfg(all(
    feature = "wasm",
    feature = "wasm-simd-msm",
    target_arch = "wasm32",
    target_feature = "simd128",
    not(feature = "parallel")
))]
pub(crate) mod simd_self_test;

use std::{
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    AffineRepr, CurveGroup, PrimeGroup,
    short_weierstrass::{Affine, Projective},
};
use ark_ff::{BigInt, PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use curvy_witness::{Limits, WitnessError, sage::SageGraph};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ProofBundle, ProverMode, SPARROW_PROFILE, msm::WindowBuckets, proof_to_snarkjs_json,
    publics_to_json,
};

/// Persistent window buckets of SPARROW's G1 and G2 queries: arkworks'
/// batch-affine buckets, or under `wasm-simd-msm` (wasm32 with simd128) the
/// SIMD kernel's buckets, which keep the same schedule in 29-bit limbs.
#[cfg(not(all(
    feature = "wasm-simd-msm",
    target_arch = "wasm32",
    target_feature = "simd128"
)))]
type G1Windows = crate::msm::AffineBuckets<ark_bn254::g1::Config>;
#[cfg(not(all(
    feature = "wasm-simd-msm",
    target_arch = "wasm32",
    target_feature = "simd128"
)))]
type G2Windows = crate::msm::AffineBuckets<ark_bn254::g2::Config>;
#[cfg(all(
    feature = "wasm-simd-msm",
    target_arch = "wasm32",
    target_feature = "simd128"
))]
type G1Windows = crate::msm_simd::SparrowG1;
#[cfg(all(
    feature = "wasm-simd-msm",
    target_arch = "wasm32",
    target_feature = "simd128"
))]
type G2Windows = crate::msm_simd::SparrowG2;

const FILE_HEADER_BYTES: usize = 12;
const SECTION_HEADER_BYTES: usize = 12;
const GROTH_HEADER_BYTES: usize = 660;
const COEFFICIENT_BYTES: usize = 44;
const G1_BYTES: usize = 64;
const G2_BYTES: usize = 128;
const ZKEY_SECTIONS: u32 = 10;
const MAX_PUBLIC_INPUTS: usize = 65_536;
// A hard resource ceiling also applies to the low-level externally authenticated
// builder: two initial QAP arrays total at most 256 MiB, not 128 GiB.
const MAX_DOMAIN_SIZE: usize = 1 << 22;
const MAX_CONTRIBUTIONS_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StreamingError {
    #[error("expected zkey SHA-256 must be exactly 64 hexadecimal characters")]
    InvalidExpectedHash,
    #[error("zkey SHA-256 mismatch: expected {expected}, got {actual}")]
    ZkeyHashMismatch { expected: String, actual: String },
    #[error("zkey manifest SHA-256 mismatch: expected {expected}, got {actual}")]
    ManifestHashMismatch { expected: String, actual: String },
    #[error("zkey manifest identifies {actual}, but protocol metadata pins {expected}")]
    ManifestZkeyHashMismatch { expected: String, actual: String },
    #[error("zkey chunk {index} SHA-256 mismatch: expected {expected}, got {actual}")]
    ZkeyChunkHashMismatch {
        index: usize,
        expected: String,
        actual: String,
    },
    #[error("invalid zkey for SPARROW: {0}")]
    InvalidZkey(String),
    #[error("zkey stream ended early")]
    UnexpectedEof,
    #[error("zkey I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Witness(#[from] WitnessError),
    #[error("Groth16 verification failed: {0}")]
    Verification(String),
    #[error("generated Groth16 proof did not verify")]
    SelfVerificationFailed,
}

impl From<crate::artifacts::manifest::ArtifactError> for StreamingError {
    fn from(error: crate::artifacts::manifest::ArtifactError) -> Self {
        use crate::artifacts::manifest::ArtifactError as A;
        match error {
            A::InvalidExpectedHash => Self::InvalidExpectedHash,
            A::ZkeyHashMismatch { expected, actual } => Self::ZkeyHashMismatch { expected, actual },
            A::ManifestHashMismatch { expected, actual } => {
                Self::ManifestHashMismatch { expected, actual }
            }
            A::ManifestZkeyHashMismatch { expected, actual } => {
                Self::ManifestZkeyHashMismatch { expected, actual }
            }
            A::ZkeyChunkHashMismatch {
                index,
                expected,
                actual,
            } => Self::ZkeyChunkHashMismatch {
                index,
                expected,
                actual,
            },
            A::InvalidZkey(message) => Self::InvalidZkey(message),
            A::UnexpectedEof => Self::UnexpectedEof,
            A::Io(error) => Self::Io(error),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StreamingConfig {
    /// Signed-Pippenger window width. Use [`Self::ADAPTIVE_WINDOW_BITS`] to
    /// select the query-size policy; explicit widths remain available for
    /// WASM/device-specific tuning.
    pub window_bits: usize,
    /// Decoded bases retained before they are folded into the persistent
    /// buckets. This is a speed/memory knob, not an artifact chunk requirement.
    pub msm_chunk_points: usize,
    /// I/O buffer used by the native `Read + Seek` adapter.
    pub io_chunk_bytes: usize,
}

/// First-pass digest state for hosts whose artifact source is itself a stream
/// (for example a cached browser `Response`).
pub struct StreamingAuthenticator {
    expected_sha256: String,
    hasher: Sha256,
    bytes: u64,
}

impl StreamingAuthenticator {
    pub fn new(expected_sha256: &str) -> Result<Self, StreamingError> {
        Ok(Self {
            expected_sha256: normalize_hash(expected_sha256)?,
            hasher: Sha256::new(),
            bytes: 0,
        })
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<(), StreamingError> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| StreamingError::InvalidZkey("artifact byte count overflow".into()))?;
        self.hasher.update(bytes);
        Ok(())
    }

    pub fn finish(self) -> Result<u64, StreamingError> {
        let actual = hex_digest(self.hasher.finalize());
        if actual != self.expected_sha256 {
            return Err(StreamingError::ZkeyHashMismatch {
                expected: self.expected_sha256,
                actual,
            });
        }
        Ok(self.bytes)
    }
}

impl Default for StreamingConfig {
    fn default() -> Self {
        // Use a stable cross-target baseline. Native hosts can select the
        // query-size policy with `native_adaptive`; browser and mobile hosts
        // can pin values established on their deployment devices.
        Self {
            window_bits: 13,
            msm_chunk_points: 65_536,
            io_chunk_bytes: 1024 * 1024,
        }
    }
}

impl StreamingConfig {
    /// Sentinel selecting a window from the number of points in each query.
    ///
    /// Window choice changes only the MSM execution schedule. It does not
    /// change the witness, proving key, curve operations, or resulting proof.
    pub const ADAPTIVE_WINDOW_BITS: usize = 0;

    /// Starting policy for native hosts with enough memory for larger batches.
    ///
    /// The MSM window is resolved independently for each query from its point
    /// count. Hosts with a device-specific profile can still override either
    /// knob explicitly.
    pub fn native_adaptive() -> Self {
        Self {
            window_bits: Self::ADAPTIVE_WINDOW_BITS,
            msm_chunk_points: 524_288,
            ..Self::default()
        }
    }

    /// Whether each query will select its window from its authenticated size.
    pub fn uses_adaptive_window(self) -> bool {
        self.window_bits == Self::ADAPTIVE_WINDOW_BITS
    }

    fn validate(self) -> Result<Self, StreamingError> {
        if !self.uses_adaptive_window() && !(4..=16).contains(&self.window_bits) {
            return invalid("MSM window bits must be 0 (adaptive) or in 4..=16");
        }
        if !(1..=1_048_576).contains(&self.msm_chunk_points) {
            return invalid("MSM chunk points must be in 1..=1048576");
        }
        if !(FILE_HEADER_BYTES..=8 * 1024 * 1024).contains(&self.io_chunk_bytes) {
            return invalid("I/O chunk bytes must be in 12..=8388608");
        }
        Ok(self)
    }
}

/// SPARROW streaming prover whose large proving key is never materialized.
pub struct StreamingProver {
    graph: SageGraph,
    expected_zkey_sha256: String,
    config: StreamingConfig,
}

impl StreamingProver {
    pub const MODE: ProverMode = ProverMode::Streaming;
    pub const PROFILE: &'static str = SPARROW_PROFILE;

    pub const fn mode(&self) -> ProverMode {
        Self::MODE
    }

    pub const fn profile(&self) -> &'static str {
        Self::PROFILE
    }

    pub fn from_signet_bytes(
        graph: &[u8],
        expected_graph_sha256: &str,
        expected_zkey_sha256: &str,
        limits: Limits,
        config: StreamingConfig,
    ) -> Result<Self, StreamingError> {
        let expected_zkey_sha256 = normalize_hash(expected_zkey_sha256)?;
        let graph = SageGraph::from_bytes_with_limits(graph, expected_graph_sha256, limits)?;
        Ok(Self {
            graph,
            expected_zkey_sha256,
            config: config.validate()?,
        })
    }

    pub fn from_compiled_sage_bytes(
        program: &[u8],
        expected_program_sha256: &str,
        expected_source_graph_sha256: &str,
        expected_zkey_sha256: &str,
        limits: Limits,
        config: StreamingConfig,
    ) -> Result<Self, StreamingError> {
        let expected_zkey_sha256 = normalize_hash(expected_zkey_sha256)?;
        let graph = SageGraph::from_compiled_bytes_with_limits(
            program,
            expected_program_sha256,
            expected_source_graph_sha256,
            limits,
        )?;
        Ok(Self {
            graph,
            expected_zkey_sha256,
            config: config.validate()?,
        })
    }

    pub fn assignment_size(&self) -> usize {
        self.graph.assignment_size()
    }

    pub fn sage_slot_count(&self) -> usize {
        self.graph.slot_count()
    }

    /// Serialize the SAGE program derived from the already authenticated graph.
    ///
    /// Browser hosts use this once to populate a versioned, origin-local cache.
    /// Loading that cache still validates its digest and embedded source-graph
    /// digest through [`Self::from_compiled_sage_bytes`].
    pub fn compiled_sage_bytes(&self) -> Result<Vec<u8>, StreamingError> {
        Ok(self.graph.to_compiled_bytes()?)
    }

    pub fn calculate_witness_json(&self, input_json: &str) -> Result<Vec<Fr>, StreamingError> {
        Ok(self.graph.calculate_json(input_json)?)
    }

    /// Authenticate, rewind, stream-prove, and self-verify one input.
    pub fn prove_json<R: Read + Seek>(
        &self,
        input_json: &str,
        zkey: &mut R,
    ) -> Result<ProofBundle, StreamingError> {
        let assignment = self.calculate_witness_json(input_json)?;
        prove_reader_owned(zkey, assignment, &self.expected_zkey_sha256, self.config)
    }

    /// Authenticate a pinned chunk manifest, then prove while reading the zkey
    /// exactly once. Every chunk is authenticated before its bytes reach the
    /// zkey parser.
    pub fn prove_json_with_manifest<R: Read>(
        &self,
        input_json: &str,
        zkey: &mut R,
        manifest_bytes: &[u8],
        expected_manifest_sha256: &str,
    ) -> Result<ProofBundle, StreamingError> {
        let manifest = manifest::ZkeyChunkManifest::from_bytes(
            manifest_bytes,
            expected_manifest_sha256,
            &self.expected_zkey_sha256,
        )?;
        let assignment = self.calculate_witness_json(input_json)?;
        manifest::prove_reader_with_manifest_owned(zkey, assignment, manifest, self.config)
    }

    pub fn prove_assignment<R: Read + Seek>(
        &self,
        assignment: &[Fr],
        zkey: &mut R,
    ) -> Result<ProofBundle, StreamingError> {
        prove_reader(zkey, assignment, &self.expected_zkey_sha256, self.config)
    }
}

/// Incremental proof state used by both native files and browser `Response.body`
/// streams. Headers are supplied separately so the JavaScript adapter only has
/// to frame 12 bytes at a time; all zkey semantics stay in Rust.
///
/// # Artifact authentication
///
/// Bulk query points use unchecked arkworks construction after their bytes have
/// crossed the artifact-authentication boundary. Callers must therefore either
/// authenticate the complete zkey before feeding this builder or use the
/// manifest adapter, which authenticates every complete chunk first. The hash
/// accumulated by [`Self::new`] checks final equality but does not by itself
/// authorize bytes before they are processed.
pub struct StreamingProofBuilder {
    assignment: Option<Arc<[Fr]>>,
    public_inputs: Option<Vec<Fr>>,
    expected_sha256: String,
    config: StreamingConfig,
    max_domain_size: usize,
    hasher: Option<Sha256>,
    began: bool,
    seen_sections: [bool; (ZKEY_SECTIONS + 1) as usize],
    section_count: u32,
    active: Option<ActiveSection>,
    header: Option<GrothHeader>,
    ic: Option<Vec<G1Affine>>,
    h: Option<Arc<[Fr]>>,
    num_constraints: Option<usize>,
    a_msm: Option<G1Projective>,
    b1_msm: Option<G1Projective>,
    b2_msm: Option<G2Projective>,
    l_msm: Option<G1Projective>,
    h_msm: Option<G1Projective>,
}

impl StreamingProofBuilder {
    /// Low-level framing API. Authenticate all bytes before supplying them,
    /// using an immutable snapshot or pinned chunk manifest. The final digest
    /// is only an equality check; it cannot authorize prior allocations.
    /// Domains above 2^22 are rejected before QAP allocation.
    pub fn new(
        assignment: Vec<Fr>,
        expected_sha256: &str,
        config: StreamingConfig,
    ) -> Result<Self, StreamingError> {
        Self::new_with_hashing(assignment, expected_sha256, config, true)
    }

    /// The manifest stream authenticates each complete chunk before it reaches
    /// this builder. Re-hashing the complete zkey here would authenticate the
    /// same bytes twice without strengthening that trust boundary.
    fn new_manifest_authenticated(
        assignment: Vec<Fr>,
        expected_sha256: &str,
        config: StreamingConfig,
    ) -> Result<Self, StreamingError> {
        Self::new_with_hashing(assignment, expected_sha256, config, false)
    }

    /// Further bound dimensions using a length obtained from authentication.
    pub(crate) fn with_authenticated_length(mut self, bytes: u64) -> Self {
        self.max_domain_size = (bytes / G1_BYTES as u64).min(MAX_DOMAIN_SIZE as u64) as usize;
        self
    }

    fn new_with_hashing(
        assignment: Vec<Fr>,
        expected_sha256: &str,
        config: StreamingConfig,
        hash_zkey: bool,
    ) -> Result<Self, StreamingError> {
        if assignment.first() != Some(&Fr::from(1_u64)) {
            return invalid("witness assignment must begin with constant one");
        }
        Ok(Self {
            assignment: Some(assignment.into()),
            public_inputs: None,
            expected_sha256: normalize_hash(expected_sha256)?,
            config: config.validate()?,
            max_domain_size: MAX_DOMAIN_SIZE,
            hasher: hash_zkey.then(Sha256::new),
            began: false,
            seen_sections: [false; (ZKEY_SECTIONS + 1) as usize],
            section_count: 0,
            active: None,
            header: None,
            ic: None,
            h: None,
            num_constraints: None,
            a_msm: None,
            b1_msm: None,
            b2_msm: None,
            l_msm: None,
            h_msm: None,
        })
    }

    pub fn begin_zkey(&mut self, header: &[u8]) -> Result<(), StreamingError> {
        if self.began || self.active.is_some() || header.len() != FILE_HEADER_BYTES {
            return invalid("invalid or duplicate zkey file header");
        }
        if &header[..4] != b"zkey"
            || le_u32(&header[4..8])? != 1
            || le_u32(&header[8..12])? != ZKEY_SECTIONS
        {
            return invalid("unsupported zkey file header");
        }
        if let Some(hasher) = &mut self.hasher {
            hasher.update(header);
        }
        self.began = true;
        Ok(())
    }

    pub fn begin_section(&mut self, section_header: &[u8]) -> Result<(), StreamingError> {
        if !self.began || self.active.is_some() || section_header.len() != SECTION_HEADER_BYTES {
            return invalid("section began in an invalid stream state");
        }
        let id = le_u32(&section_header[..4])?;
        let length = le_u64(&section_header[4..])?;
        if id == 0 || id > ZKEY_SECTIONS || self.seen_sections[id as usize] {
            return invalid(format!("invalid or duplicate zkey section {id}"));
        }
        let processor = self.processor_for(id, length)?;
        if let Some(hasher) = &mut self.hasher {
            hasher.update(section_header);
        }
        self.active = Some(ActiveSection {
            id,
            length,
            received: 0,
            processor,
        });
        Ok(())
    }

    pub fn push_section_chunk(&mut self, bytes: &[u8]) -> Result<(), StreamingError> {
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| StreamingError::InvalidZkey("no active zkey section".into()))?;
        let next = active
            .received
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| StreamingError::InvalidZkey("section byte count overflow".into()))?;
        if next > active.length {
            return invalid(format!(
                "zkey section {} exceeded its declared size",
                active.id
            ));
        }
        active.processor.push(bytes)?;
        active.received = next;
        if let Some(hasher) = &mut self.hasher {
            hasher.update(bytes);
        }
        Ok(())
    }

    pub fn end_section(&mut self) -> Result<(), StreamingError> {
        let active = self
            .active
            .take()
            .ok_or_else(|| StreamingError::InvalidZkey("no active zkey section".into()))?;
        if active.received != active.length {
            self.active = Some(active);
            return invalid("zkey section ended before its declared size");
        }

        match (active.id, active.processor) {
            (1, SectionProcessor::Small(bytes)) => {
                if bytes.len() != 4 || le_u32(&bytes)? != 1 {
                    return invalid("zkey is not a Groth16 proving key");
                }
            }
            (2, SectionProcessor::Small(bytes)) => {
                let header = GrothHeader::parse(&bytes)?;
                if header.domain_size > self.max_domain_size {
                    return invalid("Groth16 domain exceeds authenticated zkey length");
                }
                let assignment = self.assignment()?;
                if header.n_vars != assignment.len() {
                    return invalid(format!(
                        "witness assignment length mismatch: expected {}, got {}",
                        header.n_vars,
                        assignment.len()
                    ));
                }
                let public_end = header.n_public + 1;
                let public_inputs = assignment[1..public_end].to_vec();
                self.public_inputs = Some(public_inputs);
                self.header = Some(header);
            }
            (3, SectionProcessor::Small(bytes)) => {
                let header = self.header()?;
                let points = bytes
                    .chunks_exact(G1_BYTES)
                    .map(decode_g1)
                    .collect::<Result<Vec<_>, _>>()?;
                if points.iter().any(|point| !valid_g1(point)) {
                    return invalid("invalid verification-key IC point");
                }
                if points.len() != header.n_public + 1 {
                    return invalid("verification-key IC count mismatch");
                }
                self.ic = Some(points);
            }
            (4, SectionProcessor::Coefficients(coefficients)) => {
                let (h, num_constraints) = coefficients.finish()?;
                self.h = Some(h.into());
                self.num_constraints = Some(num_constraints);
            }
            (5, SectionProcessor::G1(query)) => self.a_msm = Some(query.finish()?),
            (6, SectionProcessor::G1(query)) => self.b1_msm = Some(query.finish()?),
            (7, SectionProcessor::G2(query)) => self.b2_msm = Some(query.finish()?),
            (8, SectionProcessor::G1(query)) => self.l_msm = Some(query.finish()?),
            (9, SectionProcessor::G1(query)) => self.h_msm = Some(query.finish()?),
            (10, SectionProcessor::Ignore) => {}
            _ => return invalid("zkey section processor mismatch"),
        }
        self.seen_sections[active.id as usize] = true;
        self.section_count += 1;
        if (4..=8).all(|id| self.seen_sections[id]) {
            self.assignment = None;
        }
        if active.id == 9 {
            self.h = None;
        }
        Ok(())
    }

    pub fn finish(self) -> Result<ProofBundle, StreamingError> {
        if self.active.is_some() || !self.began || self.section_count != ZKEY_SECTIONS {
            return invalid("incomplete zkey stream");
        }
        if let Some(hasher) = self.hasher {
            let actual = hex_digest(hasher.finalize());
            if actual != self.expected_sha256 {
                return Err(StreamingError::ZkeyHashMismatch {
                    expected: self.expected_sha256,
                    actual,
                });
            }
        }

        let header = self
            .header
            .ok_or_else(|| StreamingError::InvalidZkey("missing Groth16 header".into()))?;
        let ic = self
            .ic
            .ok_or_else(|| StreamingError::InvalidZkey("missing IC query".into()))?;
        let vk = VerifyingKey::<Bn254> {
            alpha_g1: header.alpha_g1,
            beta_g2: header.beta_g2,
            gamma_g2: header.gamma_g2,
            delta_g2: header.delta_g2,
            gamma_abc_g1: ic,
        };

        let mut rng = ark_std::rand::rngs::OsRng;
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        let mut g_a = self
            .a_msm
            .ok_or_else(|| StreamingError::InvalidZkey("missing A query".into()))?;
        g_a += header.alpha_g1;
        g_a += header.delta_g1.mul_bigint(r.into_bigint());

        let mut g1_b = self
            .b1_msm
            .ok_or_else(|| StreamingError::InvalidZkey("missing B1 query".into()))?;
        g1_b += header.beta_g1;
        g1_b += header.delta_g1.mul_bigint(s.into_bigint());

        let mut g2_b = self
            .b2_msm
            .ok_or_else(|| StreamingError::InvalidZkey("missing B2 query".into()))?;
        g2_b += header.beta_g2;
        g2_b += header.delta_g2.mul_bigint(s.into_bigint());

        let mut c = g_a.mul_bigint(s.into_bigint());
        c += g1_b.mul_bigint(r.into_bigint());
        c -= header.delta_g1.mul_bigint((r * s).into_bigint());
        c += self
            .l_msm
            .ok_or_else(|| StreamingError::InvalidZkey("missing L query".into()))?;
        c += self
            .h_msm
            .ok_or_else(|| StreamingError::InvalidZkey("missing H query".into()))?;

        let proof = Proof::<Bn254> {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: c.into_affine(),
        };
        let public_inputs = self
            .public_inputs
            .as_deref()
            .ok_or_else(|| StreamingError::InvalidZkey("missing public inputs".into()))?;
        let verified =
            Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk), &proof, public_inputs)
                .map_err(|error| StreamingError::Verification(error.to_string()))?;
        if !verified {
            return Err(StreamingError::SelfVerificationFailed);
        }

        Ok(ProofBundle {
            proof_json: proof_to_snarkjs_json(&proof),
            public_signals_json: publics_to_json(public_inputs),
        })
    }

    fn header(&self) -> Result<&GrothHeader, StreamingError> {
        self.header.as_ref().ok_or_else(|| {
            StreamingError::InvalidZkey("Groth16 header must precede section".into())
        })
    }

    fn assignment(&self) -> Result<&Arc<[Fr]>, StreamingError> {
        self.assignment.as_ref().ok_or_else(|| {
            StreamingError::InvalidZkey("assignment was released before dependent query".into())
        })
    }

    fn processor_for(&self, id: u32, length: u64) -> Result<SectionProcessor, StreamingError> {
        match id {
            1 => small(length, 4),
            2 => small(length, GROTH_HEADER_BYTES),
            3 => {
                let header = self.header()?;
                if header.n_public > MAX_PUBLIC_INPUTS {
                    return invalid("zkey public input count exceeds SPARROW limit");
                }
                small(length, (header.n_public + 1) * G1_BYTES)
            }
            4 => {
                let header = self.header()?.clone();
                if length < 4 || !(length - 4).is_multiple_of(COEFFICIENT_BYTES as u64) {
                    return invalid("invalid coefficient section size");
                }
                Ok(SectionProcessor::Coefficients(Box::new(
                    CoefficientAccumulator::new(
                        header,
                        Arc::clone(self.assignment()?),
                        self.config.msm_chunk_points,
                    )?,
                )))
            }
            5 | 6 => {
                let header = self.header()?;
                query_g1(
                    length,
                    Arc::clone(self.assignment()?),
                    0,
                    header.n_vars,
                    self.config,
                )
            }
            7 => {
                let header = self.header()?;
                query_g2(
                    length,
                    Arc::clone(self.assignment()?),
                    0,
                    header.n_vars,
                    self.config,
                )
            }
            8 => {
                let header = self.header()?;
                let offset = header.n_public + 1;
                let count = header.n_vars.checked_sub(offset).ok_or_else(|| {
                    StreamingError::InvalidZkey("invalid L query dimensions".into())
                })?;
                query_g1(
                    length,
                    Arc::clone(self.assignment()?),
                    offset,
                    count,
                    self.config,
                )
            }
            9 => {
                let header = self.header()?;
                let h = self.h.as_ref().ok_or_else(|| {
                    StreamingError::InvalidZkey("coefficient section must precede H query".into())
                })?;
                query_g1(length, Arc::clone(h), 0, header.domain_size, self.config)
            }
            10 => {
                if length > MAX_CONTRIBUTIONS_BYTES {
                    return invalid("contribution section exceeds SPARROW limit");
                }
                Ok(SectionProcessor::Ignore)
            }
            _ => invalid("unsupported zkey section"),
        }
    }
}

struct ActiveSection {
    id: u32,
    length: u64,
    received: u64,
    processor: SectionProcessor,
}

enum SectionProcessor {
    Small(Vec<u8>),
    Coefficients(Box<CoefficientAccumulator>),
    G1(Box<QueryAccumulator<G1Windows>>),
    G2(Box<QueryAccumulator<G2Windows>>),
    Ignore,
}

impl SectionProcessor {
    fn push(&mut self, bytes: &[u8]) -> Result<(), StreamingError> {
        match self {
            Self::Small(value) => {
                value.extend_from_slice(bytes);
                Ok(())
            }
            Self::Coefficients(value) => value.push(bytes),
            Self::G1(value) => value.push(bytes),
            Self::G2(value) => value.push(bytes),
            Self::Ignore => Ok(()),
        }
    }
}

fn small(length: u64, expected: usize) -> Result<SectionProcessor, StreamingError> {
    if length != expected as u64 {
        return invalid(format!(
            "section size mismatch: expected {expected}, got {length}"
        ));
    }
    Ok(SectionProcessor::Small(Vec::with_capacity(expected)))
}

fn query_g1(
    length: u64,
    scalars: Arc<[Fr]>,
    scalar_offset: usize,
    count: usize,
    config: StreamingConfig,
) -> Result<SectionProcessor, StreamingError> {
    expected_query_size(length, count, G1_BYTES)?;
    Ok(SectionProcessor::G1(Box::new(QueryAccumulator::new(
        scalars,
        scalar_offset,
        count,
        G1_BYTES,
        decode_g1,
        valid_g1,
        config,
    )?)))
}

fn query_g2(
    length: u64,
    scalars: Arc<[Fr]>,
    scalar_offset: usize,
    count: usize,
    config: StreamingConfig,
) -> Result<SectionProcessor, StreamingError> {
    expected_query_size(length, count, G2_BYTES)?;
    Ok(SectionProcessor::G2(Box::new(QueryAccumulator::new(
        scalars,
        scalar_offset,
        count,
        G2_BYTES,
        decode_g2,
        valid_g2,
        config,
    )?)))
}

fn expected_query_size(length: u64, count: usize, width: usize) -> Result<(), StreamingError> {
    let expected = count
        .checked_mul(width)
        .ok_or_else(|| StreamingError::InvalidZkey("query size overflow".into()))?;
    if length != expected as u64 {
        return invalid(format!(
            "query size mismatch: expected {expected}, got {length}"
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct GrothHeader {
    n_vars: usize,
    n_public: usize,
    domain_size: usize,
    alpha_g1: G1Affine,
    beta_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g1: G1Affine,
    delta_g2: G2Affine,
}

impl GrothHeader {
    fn parse(bytes: &[u8]) -> Result<Self, StreamingError> {
        if bytes.len() != GROTH_HEADER_BYTES
            || le_u32(&bytes[..4])? != 32
            || limbs(&bytes[4..36])? != Fq::MODULUS
            || le_u32(&bytes[36..40])? != 32
            || limbs(&bytes[40..72])? != Fr::MODULUS
        {
            return invalid("invalid BN254 Groth16 header");
        }
        let n_vars = le_u32(&bytes[72..76])? as usize;
        let n_public = le_u32(&bytes[76..80])? as usize;
        let domain_size = le_u32(&bytes[80..84])? as usize;
        if n_vars <= n_public
            || domain_size == 0
            || domain_size > MAX_DOMAIN_SIZE
            || !domain_size.is_power_of_two()
        {
            return invalid("invalid Groth16 dimensions");
        }
        let mut offset = 84;
        let alpha_g1 = take_g1(bytes, &mut offset)?;
        let beta_g1 = take_g1(bytes, &mut offset)?;
        let beta_g2 = take_g2(bytes, &mut offset)?;
        let gamma_g2 = take_g2(bytes, &mut offset)?;
        let delta_g1 = take_g1(bytes, &mut offset)?;
        let delta_g2 = take_g2(bytes, &mut offset)?;
        if offset != bytes.len()
            || alpha_g1.is_zero()
            || beta_g1.is_zero()
            || beta_g2.is_zero()
            || gamma_g2.is_zero()
            || delta_g1.is_zero()
            || delta_g2.is_zero()
            || !valid_g1(&alpha_g1)
            || !valid_g1(&beta_g1)
            || !valid_g2(&beta_g2)
            || !valid_g2(&gamma_g2)
            || !valid_g1(&delta_g1)
            || !valid_g2(&delta_g2)
        {
            return invalid("invalid Groth16 verification-key anchor");
        }
        Ok(Self {
            n_vars,
            n_public,
            domain_size,
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
        })
    }
}

struct CoefficientAccumulator {
    header: GrothHeader,
    assignment: Arc<[Fr]>,
    a: Vec<Fr>,
    b: Vec<Fr>,
    carry: Vec<u8>,
    batch: Vec<u8>,
    batch_records: usize,
    declared: Option<usize>,
    seen: usize,
    max_constraint: Option<u32>,
}

impl CoefficientAccumulator {
    fn new(
        header: GrothHeader,
        assignment: Arc<[Fr]>,
        batch_records: usize,
    ) -> Result<Self, StreamingError> {
        let mut a = Vec::new();
        a.try_reserve_exact(header.domain_size)
            .map_err(|_| StreamingError::InvalidZkey("cannot allocate QAP A domain".into()))?;
        a.resize(header.domain_size, Fr::zero());
        let mut b = Vec::new();
        b.try_reserve_exact(header.domain_size)
            .map_err(|_| StreamingError::InvalidZkey("cannot allocate QAP B domain".into()))?;
        b.resize(header.domain_size, Fr::zero());
        Ok(Self {
            header,
            assignment,
            a,
            b,
            carry: Vec::with_capacity(COEFFICIENT_BYTES),
            batch: Vec::with_capacity(batch_records * COEFFICIENT_BYTES),
            batch_records,
            declared: None,
            seen: 0,
            max_constraint: None,
        })
    }

    fn push(&mut self, mut bytes: &[u8]) -> Result<(), StreamingError> {
        if self.declared.is_none() {
            let needed = 4 - self.carry.len();
            let take = needed.min(bytes.len());
            self.carry.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.carry.len() == 4 {
                self.declared = Some(le_u32(&self.carry)? as usize);
                self.carry.clear();
            } else {
                return Ok(());
            }
        }

        if !self.carry.is_empty() {
            let needed = COEFFICIENT_BYTES - self.carry.len();
            let take = needed.min(bytes.len());
            self.carry.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.carry.len() == COEFFICIENT_BYTES {
                let record = std::mem::take(&mut self.carry);
                self.queue_record(&record)?;
                self.carry = Vec::with_capacity(COEFFICIENT_BYTES);
            }
        }
        let mut records = bytes.chunks_exact(COEFFICIENT_BYTES);
        for record in &mut records {
            self.queue_record(record)?;
        }
        self.carry.extend_from_slice(records.remainder());
        Ok(())
    }

    fn queue_record(&mut self, record: &[u8]) -> Result<(), StreamingError> {
        self.batch.extend_from_slice(record);
        if self.batch.len() == self.batch_records * COEFFICIENT_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StreamingError> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let header = &self.header;
        let assignment = &self.assignment;
        let decode = |record: &[u8]| decode_coefficient(record, header, assignment);
        #[cfg(feature = "parallel")]
        let terms = self
            .batch
            .par_chunks_exact(COEFFICIENT_BYTES)
            .map(decode)
            .collect::<Result<Vec<_>, _>>()?;
        #[cfg(not(feature = "parallel"))]
        let terms = self
            .batch
            .chunks_exact(COEFFICIENT_BYTES)
            .map(decode)
            .collect::<Result<Vec<_>, _>>()?;
        for term in terms {
            if term.matrix == 0 {
                self.a[term.constraint] += term.value;
            } else {
                self.b[term.constraint] += term.value;
            }
            self.max_constraint = Some(
                self.max_constraint
                    .map_or(term.constraint as u32, |current| {
                        current.max(term.constraint as u32)
                    }),
            );
            self.seen += 1;
        }
        self.batch.clear();
        Ok(())
    }

    fn finish(mut self) -> Result<(Vec<Fr>, usize), StreamingError> {
        self.flush()?;
        if !self.carry.is_empty() || self.declared != Some(self.seen) {
            return invalid("coefficient record count mismatch");
        }
        let num_constraints = self
            .max_constraint
            .ok_or_else(|| StreamingError::InvalidZkey("empty coefficient section".into()))?
            .checked_sub(self.header.n_public as u32)
            .ok_or_else(|| StreamingError::InvalidZkey("invalid constraint count".into()))?
            as usize;
        let num_inputs = self.header.n_public + 1;
        let used = num_constraints
            .checked_add(num_inputs)
            .ok_or_else(|| StreamingError::InvalidZkey("QAP domain overflow".into()))?;
        let domain = GeneralEvaluationDomain::<Fr>::new(used)
            .ok_or_else(|| StreamingError::InvalidZkey("QAP domain is too large".into()))?;
        if domain.size() != self.header.domain_size {
            return invalid("zkey domain size does not match its constraints");
        }

        self.a[num_constraints..].fill(Fr::zero());
        self.b[num_constraints..].fill(Fr::zero());
        self.a[num_constraints..num_constraints + num_inputs]
            .copy_from_slice(&self.assignment[..num_inputs]);
        let h = circom_witness_map(domain, self.a, self.b, num_constraints)?;
        Ok((h, num_constraints))
    }
}

struct CoefficientTerm {
    matrix: usize,
    constraint: usize,
    value: Fr,
}

fn decode_coefficient(
    record: &[u8],
    header: &GrothHeader,
    assignment: &[Fr],
) -> Result<CoefficientTerm, StreamingError> {
    let matrix = le_u32(&record[..4])? as usize;
    let constraint = le_u32(&record[4..8])? as usize;
    let signal = le_u32(&record[8..12])? as usize;
    if matrix > 1 || constraint >= header.domain_size || signal >= assignment.len() {
        return invalid("coefficient record index is out of bounds");
    }
    let value = crate::zkey::deserialize_field_fr(&mut &record[12..44])
        .map_err(|_| StreamingError::InvalidZkey("noncanonical coefficient".into()))?;
    Ok(CoefficientTerm {
        matrix,
        constraint,
        value: value * assignment[signal],
    })
}

fn circom_witness_map(
    domain: GeneralEvaluationDomain<Fr>,
    mut a: Vec<Fr>,
    mut b: Vec<Fr>,
    num_constraints: usize,
) -> Result<Vec<Fr>, StreamingError> {
    let mut c = Vec::new();
    crate::qap::finish_evaluations(domain, &mut a, &mut b, &mut c, num_constraints)
        .map_err(|error| StreamingError::InvalidZkey(format!("invalid QAP domain: {error}")))?;
    Ok(a)
}

/// A query point decoder (`decode_g1` or `decode_g2`).
type DecodePoint<P> = fn(&[u8]) -> Result<Affine<P>, StreamingError>;

/// Bounded-memory signed-Pippenger scheduling over arkworks group types.
///
/// This layer controls batching, scalar recoding, and bucket reduction. Field
/// arithmetic, curve addition/doubling, and the final Groth16 verification stay
/// in `ark-bn254`/`ark-groth16`; this is not a separate BN254 implementation
/// (except under `wasm-simd-msm`, whose buckets use the SIMD kernel's field
/// arithmetic; see `crate::msm_simd`).
/// Buckets persist across chunks in affine form; each chunk's additions are
/// applied in batch-affine form (see `crate::msm`), so every bucket is final
/// before the next chunk starts. Bases are converted to the buckets'
/// representation as they are decoded.
struct QueryAccumulator<W: WindowBuckets> {
    scalars: Arc<[Fr]>,
    scalar_offset: usize,
    expected: usize,
    seen: usize,
    record_bytes: usize,
    decode: DecodePoint<W::Curve>,
    validate: fn(&Affine<W::Curve>) -> bool,
    carry: Vec<u8>,
    pairs: Vec<(W::Base, BigInt<4>)>,
    buckets: Vec<W>,
    window_bits: usize,
    chunk_points: usize,
    first: Option<Affine<W::Curve>>,
    last: Option<Affine<W::Curve>>,
}

impl<W: WindowBuckets> QueryAccumulator<W> {
    fn new(
        scalars: Arc<[Fr]>,
        scalar_offset: usize,
        expected: usize,
        record_bytes: usize,
        decode: DecodePoint<W::Curve>,
        validate: fn(&Affine<W::Curve>) -> bool,
        config: StreamingConfig,
    ) -> Result<Self, StreamingError> {
        let scalar_end = scalar_offset
            .checked_add(expected)
            .ok_or_else(|| StreamingError::InvalidZkey("query scalar range overflow".into()))?;
        if scalar_end > scalars.len() {
            return invalid("query scalar range exceeds assignment");
        }
        let window_bits = resolve_window_bits(config.window_bits, expected);
        let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(window_bits);
        let recoding_bits = windows.checked_mul(window_bits).ok_or_else(|| {
            StreamingError::InvalidZkey("signed-window bit count overflow".into())
        })?;
        // A padded top bit is necessary for signed recoding, but is not by
        // itself a field-generic proof that the final carry vanishes. SPARROW is
        // fixed to BN254 Fr; its modulus and every width it can select (explicit
        // 4..=16, or 3..=14 from the adaptive policy) satisfy that stronger
        // invariant, which the recoder tests exercise directly for 3..=16.
        if recoding_bits <= Fr::MODULUS_BIT_SIZE as usize {
            return invalid("signed-window recoding needs a carry bit");
        }
        let mut buckets = Vec::new();
        buckets
            .try_reserve_exact(windows)
            .map_err(|_| StreamingError::InvalidZkey("cannot allocate MSM windows".into()))?;
        for _ in 0..windows {
            buckets.push(W::try_new(window_bits).ok_or_else(|| {
                StreamingError::InvalidZkey("cannot allocate MSM buckets".into())
            })?);
        }
        Ok(Self {
            scalars,
            scalar_offset,
            expected,
            seen: 0,
            record_bytes,
            decode,
            validate,
            carry: Vec::with_capacity(record_bytes),
            pairs: Vec::with_capacity(config.msm_chunk_points),
            buckets,
            window_bits,
            chunk_points: config.msm_chunk_points,
            first: None,
            last: None,
        })
    }

    fn push(&mut self, mut bytes: &[u8]) -> Result<(), StreamingError> {
        if !self.carry.is_empty() {
            let needed = self.record_bytes - self.carry.len();
            let take = needed.min(bytes.len());
            self.carry.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.carry.len() == self.record_bytes {
                let record = std::mem::take(&mut self.carry);
                self.process_record(&record)?;
                self.carry = Vec::with_capacity(self.record_bytes);
            }
        }
        let mut records = bytes.chunks_exact(self.record_bytes);
        for record in &mut records {
            self.process_record(record)?;
        }
        self.carry.extend_from_slice(records.remainder());
        Ok(())
    }

    fn process_record(&mut self, record: &[u8]) -> Result<(), StreamingError> {
        if self.seen >= self.expected {
            return invalid("query contains too many points");
        }
        let point = (self.decode)(record)?;
        if self.first.is_none() {
            self.first = Some(point);
        }
        self.last = Some(point);
        let scalar = self.scalars[self.scalar_offset + self.seen];
        self.seen += 1;
        if !point.is_zero() && !scalar.is_zero() {
            self.pairs.push((W::base(&point), scalar.into_bigint()));
            if self.pairs.len() == self.chunk_points {
                self.flush();
            }
        }
        Ok(())
    }

    fn flush(&mut self) {
        if self.pairs.is_empty() {
            return;
        }
        accumulate_affine_windows(&mut self.buckets, &self.pairs, self.window_bits);
        self.pairs.clear();
    }

    fn finish(mut self) -> Result<Projective<W::Curve>, StreamingError> {
        if !self.carry.is_empty() || self.seen != self.expected {
            return invalid("query point count mismatch");
        }
        if self
            .first
            .as_ref()
            .is_some_and(|point| !(self.validate)(point))
            || self
                .last
                .as_ref()
                .is_some_and(|point| !(self.validate)(point))
        {
            return invalid("invalid query endpoint");
        }
        self.flush();
        Ok(crate::msm::reduce_affine_windows(
            &self.buckets,
            self.window_bits,
        ))
    }
}

/// Stream a zkey-encoded G1 query section through SPARROW's bucket
/// accumulator, `push_bytes` at a time, exactly as `StreamingProofBuilder`
/// does. Benchmark support only.
#[cfg(feature = "bench")]
#[doc(hidden)]
pub fn bench_query_msm_g1(
    section: &[u8],
    scalars: Arc<[Fr]>,
    config: StreamingConfig,
    push_bytes: usize,
) -> Result<G1Projective, StreamingError> {
    let count = section.len() / G1_BYTES;
    let query = QueryAccumulator::<G1Windows>::new(
        scalars,
        0,
        count,
        G1_BYTES,
        decode_g1,
        valid_g1,
        config.validate()?,
    )?;
    bench_stream_query(query, section, push_bytes)
}

/// G2 counterpart of [`bench_query_msm_g1`].
#[cfg(feature = "bench")]
#[doc(hidden)]
pub fn bench_query_msm_g2(
    section: &[u8],
    scalars: Arc<[Fr]>,
    config: StreamingConfig,
    push_bytes: usize,
) -> Result<G2Projective, StreamingError> {
    let count = section.len() / G2_BYTES;
    let query = QueryAccumulator::<G2Windows>::new(
        scalars,
        0,
        count,
        G2_BYTES,
        decode_g2,
        valid_g2,
        config.validate()?,
    )?;
    bench_stream_query(query, section, push_bytes)
}

#[cfg(feature = "bench")]
fn bench_stream_query<W: WindowBuckets>(
    mut query: QueryAccumulator<W>,
    section: &[u8],
    push_bytes: usize,
) -> Result<Projective<W::Curve>, StreamingError> {
    for chunk in section.chunks(push_bytes.max(1)) {
        query.push(chunk)?;
    }
    query.finish()
}

/// Fold one chunk of `(base, scalar)` pairs into every signed window's affine
/// buckets, leaving only the buckets resident. Shared by the streaming prover
/// and `phase_bench`, so the benchmark times the production kernel.
fn accumulate_affine_windows<W: WindowBuckets>(
    buckets: &mut [W],
    pairs: &[(W::Base, BigInt<4>)],
    window_bits: usize,
) {
    #[cfg(feature = "parallel")]
    buckets
        .par_iter_mut()
        .enumerate()
        .for_each(|(window, buckets)| {
            for (base, scalar) in pairs {
                buckets.add_digit(signed_window_digit(scalar, window_bits, window), base);
            }
            buckets.finish();
            buckets.release_scratch();
        });
    #[cfg(not(feature = "parallel"))]
    {
        let windows = buckets.len();
        let mut signed_digits = (0..windows)
            .map(|_| Vec::with_capacity(pairs.len()))
            .collect::<Vec<_>>();
        for (_, scalar) in pairs {
            for_each_signed_window(scalar, window_bits, windows, |window, digit| {
                signed_digits[window].push(digit);
            });
        }
        for (buckets, digits) in buckets.iter_mut().zip(&signed_digits) {
            for ((base, _), &digit) in pairs.iter().zip(digits) {
                buckets.add_digit(digit, base);
            }
            buckets.finish();
            buckets.release_scratch();
        }
    }
}

fn resolve_window_bits(configured: usize, points: usize) -> usize {
    if configured != StreamingConfig::ADAPTIVE_WINDOW_BITS {
        return configured;
    }

    crate::msm::adaptive_window_bits(points)
}

#[cfg(any(not(feature = "parallel"), test))]
fn for_each_signed_window(
    scalar: &BigInt<4>,
    width: usize,
    windows: usize,
    emit: impl FnMut(usize, i16),
) {
    crate::msm::for_each_signed_window(scalar, width, windows, emit);
}

#[cfg(any(feature = "parallel", test))]
fn signed_window_digit(scalar: &BigInt<4>, width: usize, window: usize) -> i16 {
    crate::msm::signed_window_digit(scalar, width, window)
}

fn valid_g1(point: &G1Affine) -> bool {
    point.is_zero() || (point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve())
}

fn valid_g2(point: &G2Affine) -> bool {
    point.is_zero() || (point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve())
}

fn take_g1(bytes: &[u8], offset: &mut usize) -> Result<G1Affine, StreamingError> {
    let end = offset
        .checked_add(G1_BYTES)
        .ok_or_else(|| StreamingError::InvalidZkey("point offset overflow".into()))?;
    let point = decode_g1(
        bytes
            .get(*offset..end)
            .ok_or_else(|| StreamingError::InvalidZkey("truncated G1 point".into()))?,
    )?;
    *offset = end;
    Ok(point)
}

fn take_g2(bytes: &[u8], offset: &mut usize) -> Result<G2Affine, StreamingError> {
    let end = offset
        .checked_add(G2_BYTES)
        .ok_or_else(|| StreamingError::InvalidZkey("point offset overflow".into()))?;
    let point = decode_g2(
        bytes
            .get(*offset..end)
            .ok_or_else(|| StreamingError::InvalidZkey("truncated G2 point".into()))?,
    )?;
    *offset = end;
    Ok(point)
}

// These decoders deliberately avoid a subgroup check for every bulk query
// point. They must only be reached after the caller has established the pinned
// zkey/manifest trust boundary documented on `StreamingProofBuilder`; query
// endpoints and the verification key still receive explicit curve/subgroup
// checks, and no proof is returned without arkworks Groth16 verification.
fn decode_g1(bytes: &[u8]) -> Result<G1Affine, StreamingError> {
    if bytes.len() != 64 {
        return invalid("invalid G1 point width");
    }
    crate::zkey::deserialize_g1(&mut &bytes[..])
        .map_err(|_| StreamingError::InvalidZkey("noncanonical G1 coordinate".into()))
}

fn decode_g2(bytes: &[u8]) -> Result<G2Affine, StreamingError> {
    if bytes.len() != 128 {
        return invalid("invalid G2 point width");
    }
    crate::zkey::deserialize_g2(&mut &bytes[..])
        .map_err(|_| StreamingError::InvalidZkey("noncanonical G2 coordinate".into()))
}

fn limbs(bytes: &[u8]) -> Result<BigInt<4>, StreamingError> {
    if bytes.len() != 32 {
        return invalid("invalid field element width");
    }
    let mut words = [0_u64; 4];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        let limb: [u8; 8] = chunk
            .try_into()
            .map_err(|_| StreamingError::InvalidZkey("invalid field limb width".into()))?;
        *word = u64::from_le_bytes(limb);
    }
    Ok(BigInt(words))
}

fn le_u32(bytes: &[u8]) -> Result<u32, StreamingError> {
    bytes
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| StreamingError::InvalidZkey("invalid u32 width".into()))
}

fn le_u64(bytes: &[u8]) -> Result<u64, StreamingError> {
    bytes
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| StreamingError::InvalidZkey("invalid u64 width".into()))
}

fn normalize_hash(value: &str) -> Result<String, StreamingError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StreamingError::InvalidExpectedHash);
    }
    Ok(value.to_ascii_lowercase())
}

fn hex_digest(value: impl AsRef<[u8]>) -> String {
    value
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn invalid<T>(message: impl Into<String>) -> Result<T, StreamingError> {
    Err(StreamingError::InvalidZkey(message.into()))
}

/// Authenticate the whole file and each subsequently exposed chunk before parsing.
/// Non-seekable sources must use the independently pinned manifest adapter.
pub fn prove_reader<R: Read + Seek>(
    reader: &mut R,
    assignment: &[Fr],
    expected_sha256: &str,
    config: StreamingConfig,
) -> Result<ProofBundle, StreamingError> {
    prove_reader_owned(reader, assignment.to_vec(), expected_sha256, config)
}

/// Owned-assignment variant that avoids retaining and copying a large witness.
pub fn prove_reader_owned<R: Read + Seek>(
    reader: &mut R,
    assignment: Vec<Fr>,
    expected_sha256: &str,
    config: StreamingConfig,
) -> Result<ProofBundle, StreamingError> {
    let config = config.validate()?;
    let mut authenticated =
        crate::authenticated_reader::AuthenticatedReader::new(reader, expected_sha256)
            .map_err(authentication_error)?;
    let length = authenticated.seek(SeekFrom::End(0))?;
    authenticated.seek(SeekFrom::Start(0))?;
    let reader = &mut authenticated;
    let mut builder =
        StreamingProofBuilder::new_manifest_authenticated(assignment, expected_sha256, config)?
            .with_authenticated_length(length);
    let mut file_header = [0_u8; FILE_HEADER_BYTES];
    read_exact_stream(reader, &mut file_header)?;
    builder.begin_zkey(&file_header)?;

    let mut buffer = vec![0_u8; config.io_chunk_bytes];
    for _ in 0..ZKEY_SECTIONS {
        let mut section_header = [0_u8; SECTION_HEADER_BYTES];
        read_exact_stream(reader, &mut section_header)?;
        let mut remaining = le_u64(&section_header[4..])?;
        builder.begin_section(&section_header)?;
        while remaining != 0 {
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| StreamingError::InvalidZkey("section size overflow".into()))?;
            read_exact_stream(reader, &mut buffer[..wanted])?;
            builder.push_section_chunk(&buffer[..wanted])?;
            remaining -= wanted as u64;
        }
        builder.end_section()?;
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return invalid("trailing bytes after zkey sections");
    }
    builder.finish()
}

fn read_exact_stream<R: Read>(reader: &mut R, mut bytes: &mut [u8]) -> Result<(), StreamingError> {
    while !bytes.is_empty() {
        let count = reader.read(bytes)?;
        if count == 0 {
            return Err(StreamingError::UnexpectedEof);
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

/// Preserve the typed pin and I/O failures of the shared whole-file pass.
fn authentication_error(error: crate::ProverError) -> StreamingError {
    use crate::ProverError as P;
    match error {
        P::InvalidExpectedHash => StreamingError::InvalidExpectedHash,
        P::ZkeyHashMismatch { expected, actual } => {
            StreamingError::ZkeyHashMismatch { expected, actual }
        }
        P::ZkeyIo(error) => StreamingError::Io(error),
        error => StreamingError::InvalidZkey(format!("zkey authentication failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, UniformRand};
    use num_bigint::{BigInt as NumBigInt, Sign};

    use super::{
        StreamingConfig, for_each_signed_window, resolve_window_bits, signed_window_digit,
    };

    #[test]
    fn rejects_non_one_assignments_before_streaming() {
        for assignment in [vec![], vec![Fr::from(0_u64)], vec![Fr::from(2_u64)]] {
            assert!(
                super::StreamingProofBuilder::new(
                    assignment,
                    &"00".repeat(32),
                    StreamingConfig::default()
                )
                .is_err()
            );
        }
    }

    /// The whole-file pass must surface the same typed pin and I/O errors that
    /// callers matched before it moved into the shared authenticated reader.
    #[test]
    fn whole_file_authentication_keeps_typed_errors() {
        use std::io::{Cursor, Read, Seek, SeekFrom};

        use super::{StreamingError, prove_reader_owned};

        let key = include_bytes!("../testdata/multiplier.zkey");
        let assignment = || vec![Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)];
        let prove = |pin: &str| {
            prove_reader_owned(
                &mut Cursor::new(key),
                assignment(),
                pin,
                StreamingConfig::default(),
            )
        };
        assert!(matches!(
            prove(&"00".repeat(32)),
            Err(StreamingError::ZkeyHashMismatch { .. })
        ));
        assert!(matches!(
            prove("not-a-digest"),
            Err(StreamingError::InvalidExpectedHash)
        ));

        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk failed"))
            }
        }
        impl Seek for Failing {
            fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
                Ok(0)
            }
        }
        assert!(matches!(
            prove_reader_owned(
                &mut Failing,
                assignment(),
                &"00".repeat(32),
                StreamingConfig::default(),
            ),
            Err(StreamingError::Io(_))
        ));
    }

    #[test]
    fn untrusted_domain_is_rejected_before_allocation() {
        let key = include_bytes!("../testdata/multiplier.zkey");
        let mut cursor = 12;
        while cursor < key.len() {
            let id = u32::from_le_bytes(key[cursor..cursor + 4].try_into().unwrap());
            let size =
                u64::from_le_bytes(key[cursor + 4..cursor + 12].try_into().unwrap()) as usize;
            if id == 2 {
                let original = &key[cursor + 12..cursor + 12 + size];
                for (offset, count) in [
                    (84, 64),
                    (148, 64),
                    (212, 128),
                    (340, 128),
                    (468, 64),
                    (532, 128),
                ] {
                    let mut identity = original.to_vec();
                    identity[offset..offset + count].fill(0);
                    assert!(super::GrothHeader::parse(&identity).is_err());
                }
                let mut builder = super::StreamingProofBuilder::new(
                    vec![Fr::from(1_u64); 4],
                    &"00".repeat(32),
                    StreamingConfig::default(),
                )
                .unwrap()
                .with_authenticated_length(1);
                builder.begin_zkey(&key[..12]).unwrap();
                builder.begin_section(&key[cursor..cursor + 12]).unwrap();
                builder.push_section_chunk(original).unwrap();
                assert!(
                    builder
                        .end_section()
                        .unwrap_err()
                        .to_string()
                        .contains("authenticated zkey length")
                );
                let mut header = original.to_vec();
                header[80..84].copy_from_slice(&(1u32 << 31).to_le_bytes());
                assert!(super::GrothHeader::parse(&header).is_err());
                return;
            }
            cursor += 12 + size;
        }
        panic!("missing fixture header");
    }

    /// Streamed affine buckets equal arkworks' MSM across chunk boundaries,
    /// with record-splitting push sizes, a scalar offset, repeated bases,
    /// P and -P, identity bases, zero scalars, and repeated scalars.
    #[test]
    fn streamed_query_msm_matches_arkworks_for_g1_and_g2() {
        use std::sync::Arc;

        use ark_bn254::{G1Projective, G2Projective};
        use ark_ec::{
            CurveGroup, VariableBaseMSM,
            short_weierstrass::{Affine, SWCurveConfig},
        };

        use super::{
            G1_BYTES, G1Windows, G2_BYTES, G2Windows, QueryAccumulator, decode_g1, decode_g2,
            valid_g1, valid_g2,
        };

        fn adversarial_bases<P: SWCurveConfig<ScalarField = Fr>>(
            size: usize,
            rng: &mut impl ark_std::rand::Rng,
        ) -> Vec<Affine<P>> {
            let p = Affine::<P>::rand(rng);
            let double = (p + p).into_affine();
            (0..size)
                .map(|index| match index % 7 {
                    0 | 4 => p,
                    1 => -p,
                    3 => Affine::identity(),
                    6 => double,
                    _ => Affine::rand(rng),
                })
                .collect()
        }

        let mut rng = ark_std::test_rng();
        let (offset, size) = (3, 240);
        let mut scalars = (0..offset + size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        for index in offset..offset + size {
            match index % 5 {
                0 => scalars[index] = Fr::from(0_u64),
                1 => scalars[index] = Fr::from(1_u64),
                2 => scalars[index] = scalars[index - 1],
                _ => {}
            }
        }
        let bigints = scalars[offset..]
            .iter()
            .map(|scalar| scalar.into_bigint())
            .collect::<Vec<_>>();
        let scalars: Arc<[Fr]> = scalars.into();

        let g1 = adversarial_bases::<ark_bn254::g1::Config>(size, &mut rng);
        let g2 = adversarial_bases::<ark_bn254::g2::Config>(size, &mut rng);
        let g1_bytes = g1
            .iter()
            .flat_map(|point| point.x.0.0.into_iter().chain(point.y.0.0))
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let g2_bytes = g2
            .iter()
            .flat_map(|point| [point.x.c0, point.x.c1, point.y.c0, point.y.c1])
            .flat_map(|coordinate| coordinate.0.0)
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let expected_g1 = G1Projective::msm_bigint(&g1, &bigints);
        let expected_g2 = G2Projective::msm_bigint(&g2, &bigints);
        assert!(expected_g1 != G1Projective::default() && expected_g2 != G2Projective::default());

        let adaptive = StreamingConfig::ADAPTIVE_WINDOW_BITS;
        for (window_bits, msm_chunk_points) in
            [(4, 7), (8, 64), (13, 1_000), (16, 33), (adaptive, 5)]
        {
            let config = StreamingConfig {
                window_bits,
                msm_chunk_points,
                ..StreamingConfig::default()
            };
            let mut query = QueryAccumulator::<G1Windows>::new(
                Arc::clone(&scalars),
                offset,
                size,
                G1_BYTES,
                decode_g1,
                valid_g1,
                config,
            )
            .unwrap();
            for chunk in g1_bytes.chunks(97) {
                query.push(chunk).unwrap();
            }
            assert_eq!(query.finish().unwrap(), expected_g1, "G1 {config:?}");

            let mut query = QueryAccumulator::<G2Windows>::new(
                Arc::clone(&scalars),
                offset,
                size,
                G2_BYTES,
                decode_g2,
                valid_g2,
                config,
            )
            .unwrap();
            for chunk in g2_bytes.chunks(201) {
                query.push(chunk).unwrap();
            }
            assert_eq!(query.finish().unwrap(), expected_g2, "G2 {config:?}");
        }
    }

    #[test]
    fn adaptive_window_tracks_query_size() {
        let adaptive = StreamingConfig::ADAPTIVE_WINDOW_BITS;
        assert_eq!(resolve_window_bits(adaptive, 4_095), 8);
        assert_eq!(resolve_window_bits(adaptive, 4_096), 10);
        assert_eq!(resolve_window_bits(adaptive, 16_384), 12);
        assert_eq!(resolve_window_bits(adaptive, 65_536), 12);
        assert_eq!(resolve_window_bits(adaptive, 65_537), 12);
        assert_eq!(resolve_window_bits(adaptive, 524_288), 12);
        assert_eq!(resolve_window_bits(adaptive, 524_289), 14);
        assert_eq!(resolve_window_bits(adaptive, usize::MAX), 14);
        assert_eq!(resolve_window_bits(7, usize::MAX), 7);

        let native = StreamingConfig::native_adaptive();
        assert!(native.uses_adaptive_window());
        assert_eq!(native.msm_chunk_points, 524_288);
    }

    #[test]
    fn signed_window_recoding_reconstructs_bn254_scalars() {
        let mut rng = ark_std::rand::rngs::OsRng;
        let mut scalars = vec![
            Fr::from(0_u64),
            Fr::from(1_u64),
            Fr::from(4_095_u64),
            Fr::from(4_096_u64),
            -Fr::from(1_u64),
        ];
        scalars.extend((0..128).map(|_| Fr::rand(&mut rng)));

        // Width 3 is reachable through the adaptive policy for tiny queries.
        for width in 3..=16 {
            let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(width);
            for scalar in &scalars {
                let mut reconstructed = NumBigInt::from(0);
                let mut sequential = Vec::with_capacity(windows);
                for_each_signed_window(&scalar.into_bigint(), width, windows, |_, digit| {
                    sequential.push(digit)
                });
                for (window, sequential_digit) in sequential.iter().copied().enumerate() {
                    let digit = signed_window_digit(&scalar.into_bigint(), width, window);
                    assert_eq!(digit, sequential_digit, "width {width}, window {window}");
                    reconstructed += NumBigInt::from(digit) << (window * width);
                }

                let mut bytes = Vec::with_capacity(32);
                for word in scalar.into_bigint().0 {
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
                let expected = NumBigInt::from_bytes_le(Sign::Plus, &bytes);
                assert_eq!(reconstructed, expected, "width {width}");
            }
        }
    }
}
