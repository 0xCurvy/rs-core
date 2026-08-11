//! SPARROW, Curvy's bounded-memory Groth16 prover over a sequential snarkjs
//! zkey.
//!
//! The preferred protocol authenticates a small pinned manifest first, then
//! authenticates each zkey chunk before feeding it to the parser in a single
//! pass. A compatible whole-file-digest protocol authenticates and rewinds the
//! zkey before a separately hashed proof pass. Constraint coefficients are
//! evaluated as they arrive and every query is reduced into persistent
//! Pippenger buckets, so no zkey section and no vector of query points is
//! retained.

pub mod manifest;
#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod phase_bench;

use std::{
    io::{Read, Seek, SeekFrom},
    ops::{AddAssign, SubAssign},
    sync::Arc,
};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInt, PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use curvy_witness::{Limits, WitnessError, sage::SageGraph};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ProofBundle, proof_to_snarkjs_json, publics_to_json};

const FILE_HEADER_BYTES: usize = 12;
const SECTION_HEADER_BYTES: usize = 12;
const GROTH_HEADER_BYTES: usize = 660;
const COEFFICIENT_BYTES: usize = 44;
const G1_BYTES: usize = 64;
const G2_BYTES: usize = 128;
const ZKEY_SECTIONS: u32 = 10;
const MAX_PUBLIC_INPUTS: usize = 65_536;
const MAX_CONTRIBUTIONS_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum SparrowError {
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

#[derive(Debug, Clone, Copy)]
pub struct SparrowConfig {
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
pub struct SparrowAuthenticator {
    expected_sha256: String,
    hasher: Sha256,
    bytes: u64,
}

impl SparrowAuthenticator {
    pub fn new(expected_sha256: &str) -> Result<Self, SparrowError> {
        Ok(Self {
            expected_sha256: normalize_hash(expected_sha256)?,
            hasher: Sha256::new(),
            bytes: 0,
        })
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<(), SparrowError> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| SparrowError::InvalidZkey("artifact byte count overflow".into()))?;
        self.hasher.update(bytes);
        Ok(())
    }

    pub fn finish(self) -> Result<u64, SparrowError> {
        let actual = hex_digest(self.hasher.finalize());
        if actual != self.expected_sha256 {
            return Err(SparrowError::ZkeyHashMismatch {
                expected: self.expected_sha256,
                actual,
            });
        }
        Ok(self.bytes)
    }
}

impl Default for SparrowConfig {
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

impl SparrowConfig {
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

    fn validate(self) -> Result<Self, SparrowError> {
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

/// SAGE-backed circuit bundle whose large proving key is never materialized.
pub struct SparrowProver {
    graph: SageGraph,
    expected_zkey_sha256: String,
    config: SparrowConfig,
}

impl SparrowProver {
    pub fn from_signet_bytes(
        graph: &[u8],
        expected_graph_sha256: &str,
        expected_zkey_sha256: &str,
        limits: Limits,
        config: SparrowConfig,
    ) -> Result<Self, SparrowError> {
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
        config: SparrowConfig,
    ) -> Result<Self, SparrowError> {
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
    pub fn compiled_sage_bytes(&self) -> Result<Vec<u8>, SparrowError> {
        Ok(self.graph.to_compiled_bytes()?)
    }

    pub fn calculate_witness_json(&self, input_json: &str) -> Result<Vec<Fr>, SparrowError> {
        Ok(self.graph.calculate_json(input_json)?)
    }

    /// Authenticate, rewind, stream-prove, and self-verify one input.
    pub fn prove_json<R: Read + Seek>(
        &self,
        input_json: &str,
        zkey: &mut R,
    ) -> Result<ProofBundle, SparrowError> {
        let assignment = self.calculate_witness_json(input_json)?;
        authenticate_reader(zkey, &self.expected_zkey_sha256, self.config.io_chunk_bytes)?;
        zkey.seek(SeekFrom::Start(0))?;
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
    ) -> Result<ProofBundle, SparrowError> {
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
    ) -> Result<ProofBundle, SparrowError> {
        authenticate_reader(zkey, &self.expected_zkey_sha256, self.config.io_chunk_bytes)?;
        zkey.seek(SeekFrom::Start(0))?;
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
pub struct SparrowProofBuilder {
    assignment: Option<Arc<[Fr]>>,
    public_inputs: Option<Vec<Fr>>,
    expected_sha256: String,
    config: SparrowConfig,
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

impl SparrowProofBuilder {
    pub fn new(
        assignment: Vec<Fr>,
        expected_sha256: &str,
        config: SparrowConfig,
    ) -> Result<Self, SparrowError> {
        Self::new_with_hashing(assignment, expected_sha256, config, true)
    }

    /// The manifest stream authenticates each complete chunk before it reaches
    /// this builder. Re-hashing the complete zkey here would authenticate the
    /// same bytes twice without strengthening that trust boundary.
    fn new_manifest_authenticated(
        assignment: Vec<Fr>,
        expected_sha256: &str,
        config: SparrowConfig,
    ) -> Result<Self, SparrowError> {
        Self::new_with_hashing(assignment, expected_sha256, config, false)
    }

    fn new_with_hashing(
        assignment: Vec<Fr>,
        expected_sha256: &str,
        config: SparrowConfig,
        hash_zkey: bool,
    ) -> Result<Self, SparrowError> {
        Ok(Self {
            assignment: Some(assignment.into()),
            public_inputs: None,
            expected_sha256: normalize_hash(expected_sha256)?,
            config: config.validate()?,
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

    pub fn begin_zkey(&mut self, header: &[u8]) -> Result<(), SparrowError> {
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

    pub fn begin_section(&mut self, section_header: &[u8]) -> Result<(), SparrowError> {
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

    pub fn push_section_chunk(&mut self, bytes: &[u8]) -> Result<(), SparrowError> {
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| SparrowError::InvalidZkey("no active zkey section".into()))?;
        let next = active
            .received
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| SparrowError::InvalidZkey("section byte count overflow".into()))?;
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

    pub fn end_section(&mut self) -> Result<(), SparrowError> {
        let active = self
            .active
            .take()
            .ok_or_else(|| SparrowError::InvalidZkey("no active zkey section".into()))?;
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

    pub fn finish(self) -> Result<ProofBundle, SparrowError> {
        if self.active.is_some() || !self.began || self.section_count != ZKEY_SECTIONS {
            return invalid("incomplete zkey stream");
        }
        if let Some(hasher) = self.hasher {
            let actual = hex_digest(hasher.finalize());
            if actual != self.expected_sha256 {
                return Err(SparrowError::ZkeyHashMismatch {
                    expected: self.expected_sha256,
                    actual,
                });
            }
        }

        let header = self
            .header
            .ok_or_else(|| SparrowError::InvalidZkey("missing Groth16 header".into()))?;
        let ic = self
            .ic
            .ok_or_else(|| SparrowError::InvalidZkey("missing IC query".into()))?;
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
            .ok_or_else(|| SparrowError::InvalidZkey("missing A query".into()))?;
        g_a += header.alpha_g1;
        g_a += header.delta_g1.mul_bigint(r.into_bigint());

        let mut g1_b = self
            .b1_msm
            .ok_or_else(|| SparrowError::InvalidZkey("missing B1 query".into()))?;
        g1_b += header.beta_g1;
        g1_b += header.delta_g1.mul_bigint(s.into_bigint());

        let mut g2_b = self
            .b2_msm
            .ok_or_else(|| SparrowError::InvalidZkey("missing B2 query".into()))?;
        g2_b += header.beta_g2;
        g2_b += header.delta_g2.mul_bigint(s.into_bigint());

        let mut c = g_a.mul_bigint(s.into_bigint());
        c += g1_b.mul_bigint(r.into_bigint());
        c -= header.delta_g1.mul_bigint((r * s).into_bigint());
        c += self
            .l_msm
            .ok_or_else(|| SparrowError::InvalidZkey("missing L query".into()))?;
        c += self
            .h_msm
            .ok_or_else(|| SparrowError::InvalidZkey("missing H query".into()))?;

        let proof = Proof::<Bn254> {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: c.into_affine(),
        };
        let public_inputs = self
            .public_inputs
            .as_deref()
            .ok_or_else(|| SparrowError::InvalidZkey("missing public inputs".into()))?;
        let verified =
            Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk), &proof, public_inputs)
                .map_err(|error| SparrowError::Verification(error.to_string()))?;
        if !verified {
            return Err(SparrowError::SelfVerificationFailed);
        }

        Ok(ProofBundle {
            proof_json: proof_to_snarkjs_json(&proof),
            public_signals_json: publics_to_json(public_inputs),
        })
    }

    fn header(&self) -> Result<&GrothHeader, SparrowError> {
        self.header
            .as_ref()
            .ok_or_else(|| SparrowError::InvalidZkey("Groth16 header must precede section".into()))
    }

    fn assignment(&self) -> Result<&Arc<[Fr]>, SparrowError> {
        self.assignment.as_ref().ok_or_else(|| {
            SparrowError::InvalidZkey("assignment was released before dependent query".into())
        })
    }

    fn processor_for(&self, id: u32, length: u64) -> Result<SectionProcessor, SparrowError> {
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
                    SparrowError::InvalidZkey("invalid L query dimensions".into())
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
                    SparrowError::InvalidZkey("coefficient section must precede H query".into())
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
    G1(Box<QueryAccumulator<G1Affine>>),
    G2(Box<QueryAccumulator<G2Affine>>),
    Ignore,
}

impl SectionProcessor {
    fn push(&mut self, bytes: &[u8]) -> Result<(), SparrowError> {
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

fn small(length: u64, expected: usize) -> Result<SectionProcessor, SparrowError> {
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
    config: SparrowConfig,
) -> Result<SectionProcessor, SparrowError> {
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
    config: SparrowConfig,
) -> Result<SectionProcessor, SparrowError> {
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

fn expected_query_size(length: u64, count: usize, width: usize) -> Result<(), SparrowError> {
    let expected = count
        .checked_mul(width)
        .ok_or_else(|| SparrowError::InvalidZkey("query size overflow".into()))?;
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
    fn parse(bytes: &[u8]) -> Result<Self, SparrowError> {
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
        if n_vars <= n_public || domain_size == 0 || !domain_size.is_power_of_two() {
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
    ) -> Result<Self, SparrowError> {
        let mut a = Vec::new();
        a.try_reserve_exact(header.domain_size)
            .map_err(|_| SparrowError::InvalidZkey("cannot allocate QAP A domain".into()))?;
        a.resize(header.domain_size, Fr::zero());
        let mut b = Vec::new();
        b.try_reserve_exact(header.domain_size)
            .map_err(|_| SparrowError::InvalidZkey("cannot allocate QAP B domain".into()))?;
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

    fn push(&mut self, mut bytes: &[u8]) -> Result<(), SparrowError> {
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

    fn queue_record(&mut self, record: &[u8]) -> Result<(), SparrowError> {
        self.batch.extend_from_slice(record);
        if self.batch.len() == self.batch_records * COEFFICIENT_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SparrowError> {
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

    fn finish(mut self) -> Result<(Vec<Fr>, usize), SparrowError> {
        self.flush()?;
        if !self.carry.is_empty() || self.declared != Some(self.seen) {
            return invalid("coefficient record count mismatch");
        }
        let num_constraints = self
            .max_constraint
            .ok_or_else(|| SparrowError::InvalidZkey("empty coefficient section".into()))?
            .checked_sub(self.header.n_public as u32)
            .ok_or_else(|| SparrowError::InvalidZkey("invalid constraint count".into()))?
            as usize;
        let num_inputs = self.header.n_public + 1;
        let used = num_constraints
            .checked_add(num_inputs)
            .ok_or_else(|| SparrowError::InvalidZkey("QAP domain overflow".into()))?;
        let domain = GeneralEvaluationDomain::<Fr>::new(used)
            .ok_or_else(|| SparrowError::InvalidZkey("QAP domain is too large".into()))?;
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
) -> Result<CoefficientTerm, SparrowError> {
    let matrix = le_u32(&record[..4])? as usize;
    let constraint = le_u32(&record[4..8])? as usize;
    let signal = le_u32(&record[8..12])? as usize;
    if matrix > 1 || constraint >= header.domain_size || signal >= assignment.len() {
        return invalid("coefficient record index is out of bounds");
    }
    let encoded = limbs(&record[12..44])?;
    let value = Fr::new_unchecked(Fr::new_unchecked(encoded).into_bigint());
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
) -> Result<Vec<Fr>, SparrowError> {
    let mut c = vec![Fr::zero(); domain.size()];
    #[cfg(feature = "parallel")]
    c[..num_constraints]
        .par_iter_mut()
        .zip(a.par_iter())
        .zip(b.par_iter())
        .for_each(|((c, a), b)| *c = *a * b);
    #[cfg(not(feature = "parallel"))]
    c[..num_constraints]
        .iter_mut()
        .zip(a.iter())
        .zip(b.iter())
        .for_each(|((c, a), b)| *c = *a * b);

    domain.ifft_in_place(&mut a);
    domain.ifft_in_place(&mut b);
    let double = GeneralEvaluationDomain::<Fr>::new(2 * domain.size())
        .ok_or_else(|| SparrowError::InvalidZkey("double QAP domain is too large".into()))?;
    let root = double.element(1);
    GeneralEvaluationDomain::<Fr>::distribute_powers_and_mul_by_const(
        &mut a,
        root,
        Fr::from(1_u64),
    );
    GeneralEvaluationDomain::<Fr>::distribute_powers_and_mul_by_const(
        &mut b,
        root,
        Fr::from(1_u64),
    );
    domain.fft_in_place(&mut a);
    domain.fft_in_place(&mut b);
    #[cfg(feature = "parallel")]
    a.par_iter_mut()
        .zip(b.par_iter())
        .for_each(|(a, b)| *a *= b);
    #[cfg(not(feature = "parallel"))]
    a.iter_mut().zip(&b).for_each(|(a, b)| *a *= b);
    drop(b);
    let mut ab = a;

    domain.ifft_in_place(&mut c);
    GeneralEvaluationDomain::<Fr>::distribute_powers_and_mul_by_const(
        &mut c,
        root,
        Fr::from(1_u64),
    );
    domain.fft_in_place(&mut c);
    #[cfg(feature = "parallel")]
    ab.par_iter_mut().zip(c).for_each(|(ab, c)| *ab -= c);
    #[cfg(not(feature = "parallel"))]
    ab.iter_mut().zip(c).for_each(|(ab, c)| *ab -= c);
    Ok(ab)
}

/// Bounded-memory signed-Pippenger scheduling over arkworks group types.
///
/// This layer controls batching, scalar recoding, and bucket reduction. Field
/// arithmetic, curve addition/doubling, and the final Groth16 verification stay
/// in `ark-bn254`/`ark-groth16`; this is not a separate BN254 implementation.
struct QueryAccumulator<G: AffineRepr<ScalarField = Fr>> {
    scalars: Arc<[Fr]>,
    scalar_offset: usize,
    expected: usize,
    seen: usize,
    record_bytes: usize,
    decode: fn(&[u8]) -> Result<G, SparrowError>,
    validate: fn(&G) -> bool,
    carry: Vec<u8>,
    pairs: Vec<(G, BigInt<4>)>,
    buckets: Vec<Vec<G::Group>>,
    window_bits: usize,
    chunk_points: usize,
    first: Option<G>,
    last: Option<G>,
}

impl<G> QueryAccumulator<G>
where
    G: AffineRepr<ScalarField = Fr> + Send + Sync,
    G::Group: Send + Sync,
    for<'a> G::Group: AddAssign<&'a G> + SubAssign<&'a G> + AddAssign<&'a G::Group>,
{
    fn new(
        scalars: Arc<[Fr]>,
        scalar_offset: usize,
        expected: usize,
        record_bytes: usize,
        decode: fn(&[u8]) -> Result<G, SparrowError>,
        validate: fn(&G) -> bool,
        config: SparrowConfig,
    ) -> Result<Self, SparrowError> {
        let scalar_end = scalar_offset
            .checked_add(expected)
            .ok_or_else(|| SparrowError::InvalidZkey("query scalar range overflow".into()))?;
        if scalar_end > scalars.len() {
            return invalid("query scalar range exceeds assignment");
        }
        let window_bits = resolve_window_bits(config.window_bits, expected);
        let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(window_bits);
        let recoding_bits = windows
            .checked_mul(window_bits)
            .ok_or_else(|| SparrowError::InvalidZkey("signed-window bit count overflow".into()))?;
        // A padded top bit is necessary for signed recoding, but is not by
        // itself a field-generic proof that the final carry vanishes. SPARROW is
        // fixed to BN254 Fr; its modulus and the allowed 4..=16 widths satisfy
        // that stronger invariant, which the recoder tests exercise directly.
        if recoding_bits <= Fr::MODULUS_BIT_SIZE as usize {
            return invalid("signed-window recoding needs a carry bit");
        }
        let bucket_count = 1_usize << (window_bits - 1);
        let mut buckets = Vec::new();
        buckets
            .try_reserve_exact(windows)
            .map_err(|_| SparrowError::InvalidZkey("cannot allocate MSM windows".into()))?;
        for _ in 0..windows {
            let mut window = Vec::new();
            window
                .try_reserve_exact(bucket_count)
                .map_err(|_| SparrowError::InvalidZkey("cannot allocate MSM buckets".into()))?;
            window.resize(bucket_count, G::Group::zero());
            buckets.push(window);
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

    fn push(&mut self, mut bytes: &[u8]) -> Result<(), SparrowError> {
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

    fn process_record(&mut self, record: &[u8]) -> Result<(), SparrowError> {
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
            self.pairs.push((point, scalar.into_bigint()));
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
        let pairs = &self.pairs;
        let window_bits = self.window_bits;
        #[cfg(feature = "parallel")]
        self.buckets
            .par_iter_mut()
            .enumerate()
            .for_each(|(window, buckets)| {
                accumulate_signed_window(buckets, pairs, window_bits, window)
            });
        #[cfg(not(feature = "parallel"))]
        {
            let windows = self.buckets.len();
            let mut signed_digits = (0..windows)
                .map(|_| Vec::with_capacity(pairs.len()))
                .collect::<Vec<_>>();
            for (_, scalar) in pairs {
                for_each_signed_window(scalar, window_bits, windows, |window, digit| {
                    signed_digits[window].push(digit);
                });
            }
            self.buckets
                .iter_mut()
                .zip(&signed_digits)
                .for_each(|(buckets, digits)| accumulate_signed_digits(buckets, pairs, digits));
        }
        self.pairs.clear();
    }

    fn finish(mut self) -> Result<G::Group, SparrowError> {
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
        Ok(reduce_windows::<G>(&self.buckets, self.window_bits))
    }
}

fn resolve_window_bits(configured: usize, points: usize) -> usize {
    if configured != SparrowConfig::ADAPTIVE_WINDOW_BITS {
        return configured;
    }

    crate::msm::adaptive_window_bits(points)
}

#[cfg(not(feature = "parallel"))]
fn accumulate_signed_digits<G>(buckets: &mut [G::Group], pairs: &[(G, BigInt<4>)], digits: &[i16])
where
    G: AffineRepr<ScalarField = Fr>,
    for<'a> G::Group: AddAssign<&'a G> + SubAssign<&'a G>,
{
    for ((base, _), digit) in pairs.iter().zip(digits) {
        match digit.cmp(&0) {
            std::cmp::Ordering::Greater => buckets[*digit as usize - 1] += base,
            std::cmp::Ordering::Less => buckets[digit.unsigned_abs() as usize - 1] -= base,
            std::cmp::Ordering::Equal => {}
        }
    }
}

#[cfg(feature = "parallel")]
fn accumulate_signed_window<G>(
    buckets: &mut [G::Group],
    pairs: &[(G, BigInt<4>)],
    width: usize,
    window: usize,
) where
    G: AffineRepr<ScalarField = Fr>,
    for<'a> G::Group: AddAssign<&'a G> + SubAssign<&'a G>,
{
    for (base, scalar) in pairs {
        let digit = signed_window_digit(scalar, width, window);
        match digit.cmp(&0) {
            std::cmp::Ordering::Greater => buckets[digit as usize - 1] += base,
            std::cmp::Ordering::Less => buckets[digit.unsigned_abs() as usize - 1] -= base,
            std::cmp::Ordering::Equal => {}
        }
    }
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

fn reduce_windows<G>(buckets: &[Vec<G::Group>], width: usize) -> G::Group
where
    G: AffineRepr<ScalarField = Fr>,
    for<'a> G::Group: AddAssign<&'a G::Group>,
{
    crate::msm::reduce_bucket_windows::<G>(buckets, width)
}

fn valid_g1(point: &G1Affine) -> bool {
    point.is_zero() || (point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve())
}

fn valid_g2(point: &G2Affine) -> bool {
    point.is_zero() || (point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve())
}

fn take_g1(bytes: &[u8], offset: &mut usize) -> Result<G1Affine, SparrowError> {
    let end = offset
        .checked_add(G1_BYTES)
        .ok_or_else(|| SparrowError::InvalidZkey("point offset overflow".into()))?;
    let point = decode_g1(
        bytes
            .get(*offset..end)
            .ok_or_else(|| SparrowError::InvalidZkey("truncated G1 point".into()))?,
    )?;
    *offset = end;
    Ok(point)
}

fn take_g2(bytes: &[u8], offset: &mut usize) -> Result<G2Affine, SparrowError> {
    let end = offset
        .checked_add(G2_BYTES)
        .ok_or_else(|| SparrowError::InvalidZkey("point offset overflow".into()))?;
    let point = decode_g2(
        bytes
            .get(*offset..end)
            .ok_or_else(|| SparrowError::InvalidZkey("truncated G2 point".into()))?,
    )?;
    *offset = end;
    Ok(point)
}

// These decoders deliberately avoid a subgroup check for every bulk query
// point. They must only be reached after the caller has established the pinned
// zkey/manifest trust boundary documented on `SparrowProofBuilder`; query
// endpoints and the verification key still receive explicit curve/subgroup
// checks, and no proof is returned without arkworks Groth16 verification.
fn decode_g1(bytes: &[u8]) -> Result<G1Affine, SparrowError> {
    if bytes.len() != G1_BYTES {
        return invalid("truncated G1 point");
    }
    let x = Fq::new_unchecked(limbs(&bytes[..32])?);
    let y = Fq::new_unchecked(limbs(&bytes[32..])?);
    Ok(if x.is_zero() && y.is_zero() {
        G1Affine::identity()
    } else {
        G1Affine::new_unchecked(x, y)
    })
}

fn decode_g2(bytes: &[u8]) -> Result<G2Affine, SparrowError> {
    if bytes.len() != G2_BYTES {
        return invalid("truncated G2 point");
    }
    let x = Fq2::new(
        Fq::new_unchecked(limbs(&bytes[..32])?),
        Fq::new_unchecked(limbs(&bytes[32..64])?),
    );
    let y = Fq2::new(
        Fq::new_unchecked(limbs(&bytes[64..96])?),
        Fq::new_unchecked(limbs(&bytes[96..])?),
    );
    Ok(if x.is_zero() && y.is_zero() {
        G2Affine::identity()
    } else {
        G2Affine::new_unchecked(x, y)
    })
}

fn limbs(bytes: &[u8]) -> Result<BigInt<4>, SparrowError> {
    if bytes.len() != 32 {
        return invalid("invalid field element width");
    }
    let mut words = [0_u64; 4];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        let limb: [u8; 8] = chunk
            .try_into()
            .map_err(|_| SparrowError::InvalidZkey("invalid field limb width".into()))?;
        *word = u64::from_le_bytes(limb);
    }
    Ok(BigInt(words))
}

fn le_u32(bytes: &[u8]) -> Result<u32, SparrowError> {
    bytes
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| SparrowError::InvalidZkey("invalid u32 width".into()))
}

fn le_u64(bytes: &[u8]) -> Result<u64, SparrowError> {
    bytes
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| SparrowError::InvalidZkey("invalid u64 width".into()))
}

fn normalize_hash(value: &str) -> Result<String, SparrowError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SparrowError::InvalidExpectedHash);
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

fn invalid<T>(message: impl Into<String>) -> Result<T, SparrowError> {
    Err(SparrowError::InvalidZkey(message.into()))
}

pub fn authenticate_reader<R: Read + Seek>(
    reader: &mut R,
    expected_sha256: &str,
    chunk_bytes: usize,
) -> Result<(), SparrowError> {
    let expected = normalize_hash(expected_sha256)?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; chunk_bytes.max(FILE_HEADER_BYTES)];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual = hex_digest(hasher.finalize());
    if actual != expected {
        return Err(SparrowError::ZkeyHashMismatch { expected, actual });
    }
    Ok(())
}

pub fn prove_reader<R: Read>(
    reader: &mut R,
    assignment: &[Fr],
    expected_sha256: &str,
    config: SparrowConfig,
) -> Result<ProofBundle, SparrowError> {
    prove_reader_owned(reader, assignment.to_vec(), expected_sha256, config)
}

/// Owned-assignment variant that avoids retaining and copying a large witness.
pub fn prove_reader_owned<R: Read>(
    reader: &mut R,
    assignment: Vec<Fr>,
    expected_sha256: &str,
    config: SparrowConfig,
) -> Result<ProofBundle, SparrowError> {
    let mut builder = SparrowProofBuilder::new(assignment, expected_sha256, config)?;
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
                .map_err(|_| SparrowError::InvalidZkey("section size overflow".into()))?;
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

fn read_exact_stream<R: Read>(reader: &mut R, mut bytes: &mut [u8]) -> Result<(), SparrowError> {
    while !bytes.is_empty() {
        let count = reader.read(bytes)?;
        if count == 0 {
            return Err(SparrowError::UnexpectedEof);
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, UniformRand};
    use num_bigint::{BigInt as NumBigInt, Sign};

    use super::{SparrowConfig, for_each_signed_window, resolve_window_bits, signed_window_digit};

    #[test]
    fn adaptive_window_tracks_query_size() {
        let adaptive = SparrowConfig::ADAPTIVE_WINDOW_BITS;
        assert_eq!(resolve_window_bits(adaptive, 32_768), 8);
        assert_eq!(resolve_window_bits(adaptive, 32_769), 9);
        assert_eq!(resolve_window_bits(adaptive, 65_537), 10);
        assert_eq!(resolve_window_bits(adaptive, 262_145), 11);
        assert_eq!(resolve_window_bits(adaptive, 524_289), 12);
        assert_eq!(resolve_window_bits(adaptive, 2_097_153), 13);
        assert_eq!(resolve_window_bits(7, usize::MAX), 7);

        let native = SparrowConfig::native_adaptive();
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

        for width in 4..=16 {
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
