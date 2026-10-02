// Migrated from ark-circom 0.6.0 (https://github.com/arkworks-rs/circom-compat),
// licensed MIT OR Apache-2.0. Local changes: the wasmer-based witness calculator
// is removed, point deserialization is unchecked with a verifying-key anchor
// spot-check (see `read_zkey`), and the bulk point sections convert in parallel
// under the `parallel` feature.
//! ZKey Parsing
//!
//! Each ZKey file is broken into sections:
//!  Header(1)
//!       Prover Type 1 Groth
//!  HeaderGroth(2)
//!       n8q
//!       q
//!       n8r
//!       r
//!       NVars
//!       NPub
//!       DomainSize  (multiple of 2
//!       alpha1
//!       beta1
//!       delta1
//!       beta2
//!       gamma2
//!       delta2
//!  IC(3)
//!  Coefs(4)
//!  PointsA(5)
//!  PointsB1(6)
//!  PointsB2(7)
//!  PointsC(8)
//!  PointsH(9)
//!  Contributions(10)
use ark_ff::{BigInteger256, PrimeField, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
#[cfg(not(feature = "compact-matrix"))]
use ark_relations::utils::matrix::Matrix;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use ark_std::log2;
use byteorder::{LittleEndian, ReadBytesExt};
#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
use sha2::{Digest, Sha256};

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use crate::phase_timing::phase;
#[cfg(feature = "compact-matrix")]
use crate::qap::CompactMatrix;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_groth16::{ProvingKey, VerifyingKey};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

type IoResult<T> = Result<T, SerializationError>;

/// The Circom matrices and metadata parsed from a snarkjs zkey.
///
/// Arkworks 0.6 accepts the three matrices directly during proof generation;
/// this container retains the metadata needed for assignment validation.
pub struct ZkeyMatrices<F> {
    pub(crate) num_instance_variables: usize,
    pub(crate) num_constraints: usize,
    #[cfg(not(feature = "compact-matrix"))]
    pub(crate) matrices: [Matrix<F>; 3],
    #[cfg(feature = "compact-matrix")]
    pub(crate) matrices: [CompactMatrix<F>; 2],
}

#[cfg(feature = "bench")]
impl<F: PrimeField> ZkeyMatrices<F> {
    pub(crate) fn storage_bytes(&self) -> usize {
        #[cfg(feature = "compact-matrix")]
        {
            self.matrices.iter().map(CompactMatrix::storage_bytes).sum()
        }
        #[cfg(not(feature = "compact-matrix"))]
        {
            self.matrices
                .iter()
                .map(|matrix| {
                    matrix.capacity() * size_of::<Vec<(F, usize)>>()
                        + matrix
                            .iter()
                            .map(|row| row.capacity() * size_of::<(F, usize)>())
                            .sum::<usize>()
                })
                .sum()
        }
    }
}

#[derive(Clone, Debug)]
struct Section {
    position: u64,
    size: usize,
}

/// Reads a SnarkJS ZKey file into an Arkworks ProvingKey.
///
/// This performs **no authentication**. Points are constructed unchecked, so
/// the artifact must already be trusted: either digest-pinned by
/// [`crate::Prover::from_zkey_bytes`] / [`crate::Prover::from_zkey_reader`],
/// or handed to [`validate_proving_key`] before its key material is used.
pub fn read_zkey<R: Read + Seek>(
    reader: &mut R,
) -> IoResult<(ProvingKey<Bn254>, ZkeyMatrices<Fr>)> {
    let mut binfile = BinFile::new(reader)?;
    let proving_key = phase!("load.zkey.points", binfile.proving_key())?;
    let matrices = phase!("load.zkey.matrices", binfile.matrices())?;
    check_domain_size(&proving_key, &matrices)?;
    phase!("load.zkey.spot_check", spot_check(&proving_key))?;
    Ok((proving_key, matrices))
}

/// Reject a Groth header whose QAP domain disagrees with its own constraints.
///
/// The prover sizes the witness map from the constraint count, not from the
/// header, and its H-query MSM pairs bases with scalars only up to the shorter
/// of the two. A larger declared domain would silently drop H bases, so
/// [`crate::Prover::prove`] would return an invalid proof instead of an error.
/// SPARROW makes the same check when it finishes section 4.
fn check_domain_size(pk: &ProvingKey<Bn254>, matrices: &ZkeyMatrices<Fr>) -> IoResult<()> {
    let used = matrices
        .num_constraints
        .checked_add(matrices.num_instance_variables)
        .ok_or(SerializationError::InvalidData)?;
    // `h_query.len()` equals the header's domain size: the section length is
    // checked against it while parsing.
    let expected = GeneralEvaluationDomain::<Fr>::new(used).map(|domain| domain.size());
    if expected != Some(pk.h_query.len()) {
        return Err(SerializationError::InvalidData);
    }
    Ok(())
}

/// Check that a proving key's CRS is internally consistent.
///
/// [`validate_proving_key`] answers "is every point a real curve point"; it
/// does not answer "do these points belong to one coherent setup". A key can be
/// built entirely from valid points and still be malformed, and a malformed key
/// is not just a liveness problem: the subversion-ZK literature (Bellare,
/// Fuchsbauer and Scafuro; Abdolmaleki, Baghery, Lipmaa and Zajac) shows a
/// crafted CRS can keep proofs verifying while leaking witness data through
/// them. The defence is to verify the CRS before trusting it, which is what
/// this does.
///
/// Three relations are checked, all without the trapdoor:
///
/// - `beta` agrees across G1 and G2;
/// - `delta` agrees across G1 and G2, which the prover's `r`/`s` blinding
///   relies on;
/// - the G1 and G2 `B` queries encode the same values, batched under fresh
///   random scalars so one multi-pairing covers every entry.
///
/// # What this does not prove
///
/// It cannot see the circuit or the ceremony, so it does not prove the key
/// encodes the intended constraints, nor that it descends from a particular
/// powers-of-tau transcript. These are necessary conditions, not sufficient
/// ones. Full assurance still comes from verifying the artifact against its
/// r1cs and a public ptau (`snarkjs zkey verify`) before its digest is pinned.
/// Run this as a second, cheap gate at that same moment - not per load.
pub fn validate_crs_consistency(pk: &ProvingKey<Bn254>) -> IoResult<()> {
    use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing};
    use ark_std::UniformRand;

    if pk.b_g1_query.len() != pk.b_g2_query.len() {
        return Err(SerializationError::InvalidData);
    }

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    // A G1/G2 pair encodes the same scalar exactly when e(x, g2) == e(g1, y),
    // which as a single multi-pairing is e(x, g2) * e(-g1, y) == 1.
    let agrees = |x: G1Affine, y: G2Affine| Bn254::multi_pairing([x, -g1], [g2, y]).is_zero();

    if !agrees(pk.beta_g1, pk.vk.beta_g2) || !agrees(pk.delta_g1, pk.vk.delta_g2) {
        return Err(SerializationError::InvalidData);
    }

    // Fresh randomness, so a key author cannot shape the batch that will check
    // them. One inconsistent entry survives the combination with overwhelming
    // probability.
    let mut rng = ark_std::rand::rngs::OsRng;
    let scalars = (0..pk.b_g1_query.len())
        .map(|_| Fr::rand(&mut rng).into_bigint())
        .collect::<Vec<_>>();
    let combined_g1 = G1Projective::msm_bigint(&pk.b_g1_query, &scalars).into_affine();
    let combined_g2 = G2Projective::msm_bigint(&pk.b_g2_query, &scalars).into_affine();
    if !agrees(combined_g1, combined_g2) {
        return Err(SerializationError::InvalidData);
    }

    Ok(())
}

/// Validate every curve point in a parsed proving key.
///
/// Normal proving loads deliberately check only anchors and query endpoints after
/// authenticating a pinned artifact. Release tooling should call this once before
/// publishing that pin so the complete static key, including every G2 subgroup,
/// has been validated without charging every client for the work.
pub fn validate_proving_key(pk: &ProvingKey<Bn254>) -> IoResult<()> {
    use ark_ec::AffineRepr;

    let valid_g1_anchor = |point: &G1Affine| {
        !point.is_zero() && point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve()
    };
    let valid_g2_anchor = |point: &G2Affine| {
        !point.is_zero() && point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve()
    };
    let valid_g1 = |point: &G1Affine| {
        point.is_zero() || (point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve())
    };
    let valid_g2 = |point: &G2Affine| {
        point.is_zero() || (point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve())
    };
    let anchors_valid = valid_g1_anchor(&pk.vk.alpha_g1)
        && valid_g1_anchor(&pk.beta_g1)
        && valid_g1_anchor(&pk.delta_g1)
        && valid_g2_anchor(&pk.vk.beta_g2)
        && valid_g2_anchor(&pk.vk.gamma_g2)
        && valid_g2_anchor(&pk.vk.delta_g2);
    let g1 = [
        &pk.vk.gamma_abc_g1,
        &pk.a_query,
        &pk.b_g1_query,
        &pk.l_query,
        &pk.h_query,
    ];
    if anchors_valid && g1.into_iter().flatten().all(valid_g1) && pk.b_g2_query.iter().all(valid_g2)
    {
        Ok(())
    } else {
        Err(SerializationError::InvalidData)
    }
}

// Cheap sanity net for the unchecked bulk deserialization: validate the vk
// anchor points plus the first/last element of every query vector. Catches
// endianness/offset misparses and gross corruption at ~a dozen curve checks;
// full artifact integrity is the caller's job (content-hash the .zkey once).
pub(crate) fn spot_check(pk: &ProvingKey<Bn254>) -> IoResult<()> {
    use ark_ec::AffineRepr;
    fn ok_g1(p: &G1Affine) -> bool {
        p.is_zero() || (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve())
    }
    fn ok_g2(p: &G2Affine) -> bool {
        p.is_zero() || (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve())
    }
    fn anchor_g1(p: &G1Affine) -> bool {
        !p.is_zero() && ok_g1(p)
    }
    fn anchor_g2(p: &G2Affine) -> bool {
        !p.is_zero() && ok_g2(p)
    }
    let ends_g1 = |v: &Vec<G1Affine>| {
        v.first().map(ok_g1).unwrap_or(true) && v.last().map(ok_g1).unwrap_or(true)
    };
    let valid = anchor_g1(&pk.vk.alpha_g1)
        && anchor_g1(&pk.beta_g1)
        && anchor_g2(&pk.vk.beta_g2)
        && anchor_g2(&pk.vk.gamma_g2)
        && anchor_g1(&pk.delta_g1)
        && anchor_g2(&pk.vk.delta_g2)
        && ends_g1(&pk.vk.gamma_abc_g1)
        && ends_g1(&pk.a_query)
        && ends_g1(&pk.b_g1_query)
        && ends_g1(&pk.l_query)
        && ends_g1(&pk.h_query)
        && pk.b_g2_query.first().map(ok_g2).unwrap_or(true)
        && pk.b_g2_query.last().map(ok_g2).unwrap_or(true);
    if !valid {
        return Err(SerializationError::InvalidData);
    }
    Ok(())
}

#[derive(Debug)]
struct BinFile<'a, R> {
    #[allow(dead_code)]
    ftype: String,
    #[allow(dead_code)]
    version: u32,
    sections: HashMap<u32, Vec<Section>>,
    reader: &'a mut R,
}

impl<'a, R: Read + Seek> BinFile<'a, R> {
    fn new(reader: &'a mut R) -> IoResult<Self> {
        let file_length = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"zkey" {
            return Err(SerializationError::InvalidData);
        }

        let version = reader.read_u32::<LittleEndian>()?;
        if version != 1 {
            return Err(SerializationError::InvalidData);
        }

        let num_sections = reader.read_u32::<LittleEndian>()?;

        let mut sections = HashMap::new();
        for _ in 0..num_sections {
            let section_id = reader.read_u32::<LittleEndian>()?;
            let section_length = reader.read_u64::<LittleEndian>()?;
            let section_position = reader.stream_position()?;
            let section_end = section_position
                .checked_add(section_length)
                .filter(|end| *end <= file_length)
                .ok_or(SerializationError::InvalidData)?;
            let section_size =
                usize::try_from(section_length).map_err(|_| SerializationError::InvalidData)?;

            let section = sections.entry(section_id).or_insert_with(Vec::new);
            section.push(Section {
                position: section_position,
                size: section_size,
            });

            reader.seek(SeekFrom::Start(section_end))?;
        }

        Ok(Self {
            ftype: "zkey".to_string(),
            version,
            sections,
            reader,
        })
    }

    fn proving_key(&mut self) -> IoResult<ProvingKey<Bn254>> {
        let header = self.groth_header()?;
        let l_query_size = header
            .n_vars
            .checked_sub(header.n_public + 1)
            .ok_or(SerializationError::InvalidData)?;
        let ic = self.ic(header.n_public)?;

        let a_query = self.a_query(header.n_vars)?;
        let b_g1_query = self.b_g1_query(header.n_vars)?;
        let b_g2_query = self.b_g2_query(header.n_vars)?;
        let l_query = self.l_query(l_query_size)?;
        let h_query = self.h_query(header.domain_size as usize)?;

        let vk = VerifyingKey::<Bn254> {
            alpha_g1: header.verifying_key.alpha_g1,
            beta_g2: header.verifying_key.beta_g2,
            gamma_g2: header.verifying_key.gamma_g2,
            delta_g2: header.verifying_key.delta_g2,
            gamma_abc_g1: ic,
        };

        let pk = ProvingKey::<Bn254> {
            vk,
            beta_g1: header.verifying_key.beta_g1,
            delta_g1: header.verifying_key.delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };

        Ok(pk)
    }

    fn get_section(&self, id: u32) -> IoResult<Section> {
        let sections = self
            .sections
            .get(&id)
            .ok_or(SerializationError::InvalidData)?;
        if sections.len() != 1 {
            return Err(SerializationError::InvalidData);
        }
        sections
            .first()
            .cloned()
            .ok_or(SerializationError::InvalidData)
    }

    fn groth_header(&mut self) -> IoResult<HeaderGroth> {
        let section = self.get_section(2)?;
        let header = HeaderGroth::new(&mut self.reader, &section)?;
        Ok(header)
    }

    fn ic(&mut self, n_public: usize) -> IoResult<Vec<G1Affine>> {
        // the range is non-inclusive so we do +1 to get all inputs
        self.g1_section(n_public + 1, 3)
    }

    /// Returns the constraint matrices and metadata corresponding to the zkey.
    #[cfg(not(feature = "compact-matrix"))]
    pub fn matrices(&mut self) -> IoResult<ZkeyMatrices<Fr>> {
        let header = self.groth_header()?;
        let section = self.get_section(4)?;
        self.reader.seek(SeekFrom::Start(section.position))?;
        parse_matrices(self.reader, &header, section.size)
    }

    /// Parse section 4 directly into two exact CSR matrices.
    ///
    /// Pass one validates every record and turns per-row counts into offsets.
    /// Pass two decodes field values into their final allocation. At no point
    /// does this path construct arkworks' nested `Vec<Vec<_>>` representation.
    #[cfg(feature = "compact-matrix")]
    pub fn matrices(&mut self) -> IoResult<ZkeyMatrices<Fr>> {
        let header = self.groth_header()?;
        let section = self.get_section(4)?;
        parse_compact_matrices(self.reader, &section, &header)
    }

    fn a_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 5)
    }

    fn b_g1_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 6)
    }

    fn b_g2_query(&mut self, n_vars: usize) -> IoResult<Vec<G2Affine>> {
        self.g2_section(n_vars, 7)
    }

    fn l_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 8)
    }

    fn h_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 9)
    }

    fn g1_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G1Affine>> {
        let section = self.get_section(section_id as u32)?;
        let expected_size = num
            .checked_mul(G1_BYTES)
            .ok_or(SerializationError::InvalidData)?;
        if section.size != expected_size {
            return Err(SerializationError::InvalidData);
        }
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g1_vec(self.reader, num)
    }

    fn g2_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G2Affine>> {
        let section = self.get_section(section_id as u32)?;
        let expected_size = num
            .checked_mul(G2_BYTES)
            .ok_or(SerializationError::InvalidData)?;
        if section.size != expected_size {
            return Err(SerializationError::InvalidData);
        }
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g2_vec(self.reader, num)
    }
}

/// Parse section 4 into arkworks' nested matrices. The reader must already be
/// positioned at the start of the section; the whole section is consumed in one
/// forward sweep, so a streaming caller can hand this its own reader.
#[cfg(not(feature = "compact-matrix"))]
fn parse_matrices<R: Read>(
    reader: &mut R,
    header: &HeaderGroth,
    section_size: usize,
) -> IoResult<ZkeyMatrices<Fr>> {
    let num_coeffs: u32 = reader.read_u32::<LittleEndian>()?;
    if (num_coeffs as usize)
        .checked_mul(44)
        .and_then(|bytes| bytes.checked_add(4))
        != Some(section_size)
    {
        return Err(SerializationError::InvalidData);
    }

    // Instantiate AB
    // Sized from an artifact-controlled field, so fail rather than abort if it
    // cannot be satisfied.
    let mut matrices = Vec::with_capacity(2);
    for _ in 0..2 {
        let mut rows: Vec<Vec<(Fr, usize)>> = Vec::new();
        rows.try_reserve_exact(header.domain_size as usize)
            .map_err(|_| SerializationError::InvalidData)?;
        rows.resize_with(header.domain_size as usize, Vec::new);
        matrices.push(rows);
    }
    let mut max_constraint_index = None;
    for _ in 0..num_coeffs {
        let matrix: u32 = reader.read_u32::<LittleEndian>()?;
        let constraint: u32 = reader.read_u32::<LittleEndian>()?;
        let signal: u32 = reader.read_u32::<LittleEndian>()?;
        if matrix > 1 || constraint >= header.domain_size || signal as usize >= header.n_vars {
            return Err(SerializationError::InvalidData);
        }

        let value: Fr = deserialize_field_fr(reader)?;
        max_constraint_index = Some(
            max_constraint_index.map_or(constraint, |current| std::cmp::max(current, constraint)),
        );
        matrices[matrix as usize][constraint as usize].push((value, signal as usize));
    }

    let num_constraints = max_constraint_index
        .ok_or(SerializationError::InvalidData)?
        .checked_sub(header.n_public as u32)
        .ok_or(SerializationError::InvalidData)? as usize;
    // Remove the public input constraints, Arkworks adds them later
    matrices.iter_mut().for_each(|m| {
        m.truncate(num_constraints);
    });
    // Move the two rows out instead of cloning them: cloning held a second full
    // copy of every retained coefficient while the source was still live.
    // `shrink_to_fit` then releases the push-growth slack one linear combination
    // at a time, so compaction never doubles the whole matrix either.
    //
    // Measured peak RSS for `Prover::from_zkey_bytes`, macOS release build:
    //   pending(50,30), 882 MiB zkey - 3076.05 -> 2802.61 MiB, load 882 -> 808 ms
    //   pending(5,30),  123 MiB zkey -  430.69 ->  392.81 MiB, load 128 -> 114 ms
    // Load gets faster because 6.46M coefficient entries are no longer copied.
    let mut rows = matrices.into_iter();
    let mut a = rows.next().ok_or(SerializationError::InvalidData)?;
    let mut b = rows.next().ok_or(SerializationError::InvalidData)?;
    for combination in a.iter_mut().chain(b.iter_mut()) {
        combination.shrink_to_fit();
    }

    Ok(ZkeyMatrices {
        num_instance_variables: header.n_public + 1,
        num_constraints,
        matrices: [a, b, vec![]],
    })
}

/// Parse section 4 into two exact CSR matrices.
///
/// Pass one validates every record and turns per-row counts into offsets. Pass
/// two decodes field values into their final allocation. At no point does this
/// path construct arkworks' nested `Vec<Vec<_>>` representation. The two passes
/// mean this needs a seekable source: a streaming caller must buffer the
/// section and hand over a cursor so both passes see identical bytes.
#[cfg(feature = "compact-matrix")]
fn parse_compact_matrices<R: Read + Seek>(
    reader: &mut R,
    section: &Section,
    header: &HeaderGroth,
) -> IoResult<ZkeyMatrices<Fr>> {
    const FIELD_BYTES: usize = 32;
    const COEFFICIENT_BYTES: usize = 3 * size_of::<u32>() + FIELD_BYTES;

    reader.seek(SeekFrom::Start(section.position))?;
    let num_coeffs = reader.read_u32::<LittleEndian>()?;
    let expected_size = size_of::<u32>()
        .checked_add(
            (num_coeffs as usize)
                .checked_mul(COEFFICIENT_BYTES)
                .ok_or(SerializationError::InvalidData)?,
        )
        .ok_or(SerializationError::InvalidData)?;
    if section.size != expected_size {
        return Err(SerializationError::InvalidData);
    }

    let domain_size = header.domain_size as usize;
    let mut row_offsets = [vec![0_u32; domain_size], vec![0_u32; domain_size]];
    let mut max_constraint_index = None;
    let mut encoded_value = [0_u8; FIELD_BYTES];
    for _ in 0..num_coeffs {
        let matrix = reader.read_u32::<LittleEndian>()?;
        let constraint = reader.read_u32::<LittleEndian>()?;
        let signal = reader.read_u32::<LittleEndian>()?;
        if matrix > 1 || constraint >= header.domain_size || signal as usize >= header.n_vars {
            return Err(SerializationError::InvalidData);
        }
        // Keep this pass sequential. Seeking through a BufReader discards its
        // buffer and turns one skip per coefficient into an underlying file
        // seek, which is catastrophic for production keys with millions of
        // coefficients. Canonical field validation still happens in pass two.
        reader.read_exact(&mut encoded_value)?;

        let count = &mut row_offsets[matrix as usize][constraint as usize];
        *count = count
            .checked_add(1)
            .ok_or(SerializationError::InvalidData)?;
        max_constraint_index = Some(
            max_constraint_index.map_or(constraint, |current| std::cmp::max(current, constraint)),
        );
    }

    let num_constraints = max_constraint_index
        .ok_or(SerializationError::InvalidData)?
        .checked_sub(header.n_public as u32)
        .ok_or(SerializationError::InvalidData)? as usize;

    let mut coefficients = [Vec::new(), Vec::new()];
    let mut signals = [Vec::new(), Vec::new()];
    for matrix in 0..2 {
        row_offsets[matrix].truncate(num_constraints);
        let mut total = 0_u32;
        for count in &mut row_offsets[matrix] {
            let row_count = *count;
            *count = total;
            total = total
                .checked_add(row_count)
                .ok_or(SerializationError::InvalidData)?;
        }
        row_offsets[matrix].push(total);
        coefficients[matrix].resize(total as usize, Fr::zero());
        signals[matrix].resize(total as usize, 0);
    }

    // Keep immutable row ends while pass two advances the insertion cursors.
    // A public unauthenticated reader may change between seeks; equal total
    // counts do not imply equal counts in each row.
    let row_ends = row_offsets.each_ref().map(|offsets| offsets[1..].to_vec());
    reader.seek(SeekFrom::Start(section.position))?;
    if reader.read_u32::<LittleEndian>()? != num_coeffs {
        return Err(SerializationError::InvalidData);
    }
    for _ in 0..num_coeffs {
        let matrix = reader.read_u32::<LittleEndian>()?;
        let constraint = reader.read_u32::<LittleEndian>()?;
        let signal = reader.read_u32::<LittleEndian>()?;
        if matrix > 1 || constraint >= header.domain_size || signal as usize >= header.n_vars {
            return Err(SerializationError::InvalidData);
        }
        let value = deserialize_field_fr(reader)?;
        if constraint as usize >= num_constraints {
            continue;
        }

        let matrix = matrix as usize;
        let row = constraint as usize;
        let position = row_offsets[matrix][row] as usize;
        if position >= row_ends[matrix][row] as usize {
            return Err(SerializationError::InvalidData);
        }
        coefficients[matrix][position] = value;
        signals[matrix][position] = signal;
        row_offsets[matrix][row] = row_offsets[matrix][row]
            .checked_add(1)
            .ok_or(SerializationError::InvalidData)?;
    }

    for (offsets, ends) in row_offsets.iter_mut().zip(&row_ends) {
        let rows = offsets.len() - 1;
        if offsets[..rows] != ends[..] {
            return Err(SerializationError::InvalidData);
        }
        offsets.copy_within(0..rows, 1);
        offsets[0] = 0;
    }

    let [a_offsets, b_offsets] = row_offsets;
    let [a_coefficients, b_coefficients] = coefficients;
    let [a_signals, b_signals] = signals;
    Ok(ZkeyMatrices {
        num_instance_variables: header.n_public + 1,
        num_constraints,
        matrices: [
            CompactMatrix::from_parts(a_offsets, a_coefficients, a_signals),
            CompactMatrix::from_parts(b_offsets, b_coefficients, b_signals),
        ],
    })
}

/// A forward-only reader that folds every byte it passes over into a SHA-256
/// digest exactly once.
///
/// It deliberately does not implement `Seek`. Rewinding is what lets a digest
/// cover different bytes than the parse consumed, so making it inexpressible is
/// the whole guarantee.
#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
struct DigestingReader<'a, R> {
    inner: &'a mut R,
    digest: Option<Sha256>,
    position: u64,
}

#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
impl<'a, R: Read> DigestingReader<'a, R> {
    fn new(inner: &'a mut R, hash_bytes: bool) -> Self {
        Self {
            inner,
            digest: hash_bytes.then(Sha256::new),
            position: 0,
        }
    }

    fn position(&self) -> u64 {
        self.position
    }

    /// Consume and hash forward to `target`, covering bytes the parser had no
    /// reason to read. Moving backwards is rejected rather than silently
    /// leaving a hole in the digest.
    fn advance_to(&mut self, target: u64) -> IoResult<()> {
        let mut remaining = target
            .checked_sub(self.position)
            .ok_or(SerializationError::InvalidData)?;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| SerializationError::InvalidData)?;
            self.inner.read_exact(&mut buffer[..wanted])?;
            if let Some(digest) = &mut self.digest {
                digest.update(&buffer[..wanted]);
            }
            self.position += wanted as u64;
            remaining -= wanted as u64;
        }
        Ok(())
    }

    fn finish(self) -> [u8; 32] {
        self.digest
            .map(|digest| digest.finalize().into())
            .unwrap_or_default()
    }
}

#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
impl<R: Read> Read for DigestingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        if let Some(digest) = &mut self.digest {
            digest.update(&buffer[..count]);
        }
        self.position += count as u64;
        Ok(count)
    }
}

/// Reject header dimensions the artifact could not possibly hold.
///
/// Every query section stores a fixed number of bytes per entry, so a count
/// whose section could not fit in the file is malformed. The seeking reader
/// gets this implicitly by parsing the queries before the matrices; the
/// streaming walk meets section 4 first and so has to check it up front.
#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
fn validate_dimensions(header: &HeaderGroth, file_length: u64) -> IoResult<()> {
    let fits = |count: usize, bytes_per_entry: usize| {
        u64::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(bytes_per_entry as u64))
            .is_some_and(|bytes| bytes <= file_length)
    };
    if fits(header.n_vars, G1_BYTES)
        && fits(header.n_vars, G2_BYTES)
        && fits(header.domain_size as usize, G1_BYTES)
    {
        Ok(())
    } else {
        Err(SerializationError::InvalidData)
    }
}

#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
fn require<T>(slot: &Option<T>) -> IoResult<&T> {
    slot.as_ref().ok_or(SerializationError::InvalidData)
}

#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
fn set_once<T>(slot: &mut Option<T>, value: T) -> IoResult<()> {
    if slot.replace(value).is_some() {
        return Err(SerializationError::InvalidData);
    }
    Ok(())
}

#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
fn g1_query<R: Read>(reader: &mut R, count: usize, size: usize) -> IoResult<Vec<G1Affine>> {
    let expected = count
        .checked_mul(G1_BYTES)
        .ok_or(SerializationError::InvalidData)?;
    if size != expected {
        return Err(SerializationError::InvalidData);
    }
    deserialize_g1_vec(reader, count)
}

#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
fn g2_query<R: Read>(reader: &mut R, count: usize, size: usize) -> IoResult<Vec<G2Affine>> {
    let expected = count
        .checked_mul(G2_BYTES)
        .ok_or(SerializationError::InvalidData)?;
    if size != expected {
        return Err(SerializationError::InvalidData);
    }
    deserialize_g2_vec(reader, count)
}

/// Parse a zkey in one forward pass, digesting every byte as it goes.
///
/// [`read_zkey`] locates each section by seeking, so authenticating it needs a
/// separate hashing pass over the file. Here the section index is interleaved
/// with the bodies it describes, so walking forward once reaches every section
/// header in file order and can parse each body where it lies. The returned
/// digest therefore covers exactly the bytes that were parsed, and the caller
/// compares it against the pin before using the key.
///
/// This requires the Groth header (section 2) to precede the query sections
/// whose lengths it fixes, which is the order snarkjs emits. A zkey ordered any
/// other way is rejected rather than silently reread. Section ids need not
/// ascend; the test fixture's do not.
///
/// This performs **no authentication of its own**: it returns the digest it
/// computed, and the caller must compare it against the pin before using the
/// key. [`crate::Prover::from_zkey_reader`] does exactly that.
#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
pub fn read_zkey_sequential<R: Read + Seek>(
    reader: &mut R,
) -> IoResult<(ProvingKey<Bn254>, ZkeyMatrices<Fr>, [u8; 32])> {
    let file_length = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    read_zkey_forward(reader, file_length, true)
}

/// The caller must authenticate every byte before Read exposes it when
/// `hash_bytes` is false. This entry point is private to the crate.
#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
pub(crate) fn read_zkey_forward<R: Read>(
    reader: &mut R,
    file_length: u64,
    hash_bytes: bool,
) -> IoResult<(ProvingKey<Bn254>, ZkeyMatrices<Fr>, [u8; 32])> {
    let mut reader = DigestingReader::new(reader, hash_bytes);

    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != b"zkey" {
        return Err(SerializationError::InvalidData);
    }
    if reader.read_u32::<LittleEndian>()? != 1 {
        return Err(SerializationError::InvalidData);
    }
    let num_sections = reader.read_u32::<LittleEndian>()?;

    let mut header = None;
    let mut ic = None;
    let mut matrices = None;
    let mut a_query = None;
    let mut b_g1_query = None;
    let mut b_g2_query = None;
    let mut l_query = None;
    let mut h_query = None;

    for _ in 0..num_sections {
        let id = reader.read_u32::<LittleEndian>()?;
        let length = reader.read_u64::<LittleEndian>()?;
        let position = reader.position();
        let end = position
            .checked_add(length)
            .filter(|end| *end <= file_length)
            .ok_or(SerializationError::InvalidData)?;
        let size = usize::try_from(length).map_err(|_| SerializationError::InvalidData)?;

        match id {
            2 => {
                let groth = HeaderGroth::read(&mut reader)?;
                // Bound the declared dimensions before anything allocates from
                // them: section 4 is parsed before section 9 in the layouts
                // snarkjs emits, so waiting for the H query's size check would
                // let a tiny file drive a huge matrix allocation first.
                validate_dimensions(&groth, file_length)?;
                set_once(&mut header, groth)?;
            }
            3 => {
                let count = require(&header)?.n_public + 1;
                set_once(&mut ic, g1_query(&mut reader, count, size)?)?;
            }
            4 => {
                let parsed = parse_section_four(&mut reader, size, require(&header)?)?;
                set_once(&mut matrices, parsed)?;
            }
            5 => {
                let count = require(&header)?.n_vars;
                set_once(&mut a_query, g1_query(&mut reader, count, size)?)?;
            }
            6 => {
                let count = require(&header)?.n_vars;
                set_once(&mut b_g1_query, g1_query(&mut reader, count, size)?)?;
            }
            7 => {
                let count = require(&header)?.n_vars;
                set_once(&mut b_g2_query, g2_query(&mut reader, count, size)?)?;
            }
            8 => {
                let groth = require(&header)?;
                let count = groth
                    .n_vars
                    .checked_sub(groth.n_public + 1)
                    .ok_or(SerializationError::InvalidData)?;
                set_once(&mut l_query, g1_query(&mut reader, count, size)?)?;
            }
            9 => {
                let count = require(&header)?.domain_size as usize;
                set_once(&mut h_query, g1_query(&mut reader, count, size)?)?;
            }
            // Contributions and any future section still have to be digested.
            _ => {}
        }
        reader.advance_to(end)?;
    }
    reader.advance_to(file_length)?;
    let digest = reader.finish();

    let header = header.ok_or(SerializationError::InvalidData)?;
    let vk = VerifyingKey::<Bn254> {
        alpha_g1: header.verifying_key.alpha_g1,
        beta_g2: header.verifying_key.beta_g2,
        gamma_g2: header.verifying_key.gamma_g2,
        delta_g2: header.verifying_key.delta_g2,
        gamma_abc_g1: ic.ok_or(SerializationError::InvalidData)?,
    };
    let proving_key = ProvingKey::<Bn254> {
        vk,
        beta_g1: header.verifying_key.beta_g1,
        delta_g1: header.verifying_key.delta_g1,
        a_query: a_query.ok_or(SerializationError::InvalidData)?,
        b_g1_query: b_g1_query.ok_or(SerializationError::InvalidData)?,
        b_g2_query: b_g2_query.ok_or(SerializationError::InvalidData)?,
        h_query: h_query.ok_or(SerializationError::InvalidData)?,
        l_query: l_query.ok_or(SerializationError::InvalidData)?,
    };
    let matrices = matrices.ok_or(SerializationError::InvalidData)?;
    check_domain_size(&proving_key, &matrices)?;
    Ok((proving_key, matrices, digest))
}

/// Section 4 for the streaming walk: read the whole section, then parse it from
/// memory.
///
/// The CSR parser needs two passes over the same bytes, and buffering is what
/// lets both see an identical snapshot. It turns out to pay for the nested
/// parser too: a production key carries about 1.6M coefficients, each decoded
/// as four small reads, and pulling those through the buffered reader costs far
/// more than one bulk copy. On a 217 MiB, 391k-constraint key this took the
/// authenticated load from 249 ms to 183 ms. These historical measurements
/// predate the default seekable reader's chunk authentication.
///
/// The buffer is transient and smaller than the matrices parsed out of it.
#[cfg(any(feature = "zkey-single-pass", feature = "zkey-manifest"))]
fn parse_section_four<R: Read>(
    reader: &mut R,
    size: usize,
    header: &HeaderGroth,
) -> IoResult<ZkeyMatrices<Fr>> {
    let mut buffered = Vec::new();
    buffered
        .try_reserve_exact(size)
        .map_err(|_| SerializationError::InvalidData)?;
    buffered.resize(size, 0);
    reader.read_exact(&mut buffered)?;
    let mut cursor = std::io::Cursor::new(buffered);

    #[cfg(not(feature = "compact-matrix"))]
    return parse_matrices(&mut cursor, header, size);
    #[cfg(feature = "compact-matrix")]
    {
        let section = Section { position: 0, size };
        parse_compact_matrices(&mut cursor, &section, header)
    }
}

#[derive(Default, Clone, Debug, CanonicalDeserialize)]
pub struct ZVerifyingKey {
    alpha_g1: G1Affine,
    beta_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g1: G1Affine,
    delta_g2: G2Affine,
}

impl ZVerifyingKey {
    fn new<R: Read>(reader: &mut R) -> IoResult<Self> {
        let alpha_g1 = deserialize_g1(reader)?;
        let beta_g1 = deserialize_g1(reader)?;
        let beta_g2 = deserialize_g2(reader)?;
        let gamma_g2 = deserialize_g2(reader)?;
        let delta_g1 = deserialize_g1(reader)?;
        let delta_g2 = deserialize_g2(reader)?;

        Ok(Self {
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
        })
    }
}

#[derive(Clone, Debug)]
struct HeaderGroth {
    #[allow(dead_code)]
    n8q: u32,
    #[allow(dead_code)]
    q: BigInteger256,
    #[allow(dead_code)]
    n8r: u32,
    #[allow(dead_code)]
    r: BigInteger256,

    n_vars: usize,
    n_public: usize,

    domain_size: u32,
    #[allow(dead_code)]
    power: u32,

    verifying_key: ZVerifyingKey,
}

impl HeaderGroth {
    fn new<R: Read + Seek>(reader: &mut R, section: &Section) -> IoResult<Self> {
        reader.seek(SeekFrom::Start(section.position))?;
        Self::read(reader)
    }

    fn read<R: Read>(mut reader: &mut R) -> IoResult<Self> {
        let n8q: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // group order r of Bn254
        let q = BigInteger256::deserialize_uncompressed(&mut reader)?;

        let n8r: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // Prime field modulus
        let r = BigInteger256::deserialize_uncompressed(&mut reader)?;

        let n_vars = u32::deserialize_uncompressed(&mut reader)? as usize;
        let n_public = u32::deserialize_uncompressed(&mut reader)? as usize;

        let domain_size: u32 = u32::deserialize_uncompressed(&mut reader)?;
        if n8q != 32
            || q != Fq::MODULUS
            || n8r != 32
            || r != Fr::MODULUS
            || n_vars <= n_public
            || domain_size == 0
            || !domain_size.is_power_of_two()
        {
            return Err(SerializationError::InvalidData);
        }
        let power = log2(domain_size as usize);

        let verifying_key = ZVerifyingKey::new(&mut reader)?;

        Ok(Self {
            n8q,
            q,
            n8r,
            r,
            n_vars,
            n_public,
            domain_size,
            power,
            verifying_key,
        })
    }
}

// need to divide by R, since snarkjs outputs the zkey with coefficients
// multiplieid by R^2
pub(crate) fn deserialize_field_fr<R: Read>(reader: &mut R) -> IoResult<Fr> {
    let bigint = BigInteger256::deserialize_uncompressed(reader)?;
    if bigint >= Fr::MODULUS {
        return Err(SerializationError::InvalidData);
    }
    Ok(Fr::new_unchecked(Fr::new_unchecked(bigint).into_bigint()))
}

// skips the multiplication by R because Circom points are already in Montgomery form
fn deserialize_field<R: Read>(reader: &mut R) -> IoResult<Fq> {
    let bigint = BigInteger256::deserialize_uncompressed(reader)?;
    // Montgomery residues must be canonical too: values outside the modulus
    // violate arkworks' arithmetic invariants before curve checks can run.
    if bigint >= Fq::MODULUS {
        return Err(SerializationError::InvalidData);
    }
    // if you use Fq::new it multiplies by R
    Ok(Fq::new_unchecked(bigint))
}

pub fn deserialize_field2<R: Read>(reader: &mut R) -> IoResult<Fq2> {
    let c0 = deserialize_field(reader)?;
    let c1 = deserialize_field(reader)?;
    Ok(Fq2::new(c0, c1))
}

// UNCHECKED point construction (vendored change vs ark-circom): upstream used
// `Affine::new`, which runs an on-curve check per point and a subgroup check
// per G2 point - for a 226k-constraint zkey that is ~1M G1 + ~230k G2 curve
// checks on EVERY load of a static, hash-pinnable artifact, and it dominated
// cold start (23 s in wasm). Integrity belongs on the ARTIFACT (content hash /
// one-time validation), not per point per load; `read_zkey` still spot-checks
// the vk anchor points, which catches gross corruption/misparse for free.
pub(crate) fn deserialize_g1<R: Read>(reader: &mut R) -> IoResult<G1Affine> {
    let x = deserialize_field(reader)?;
    let y = deserialize_field(reader)?;
    let infinity = x.is_zero() && y.is_zero();
    if infinity {
        Ok(G1Affine::identity())
    } else {
        Ok(G1Affine::new_unchecked(x, y))
    }
}

pub(crate) fn deserialize_g2<R: Read>(reader: &mut R) -> IoResult<G2Affine> {
    let f1 = deserialize_field2(reader)?;
    let f2 = deserialize_field2(reader)?;
    let infinity = f1.is_zero() && f2.is_zero();
    if infinity {
        Ok(G2Affine::identity())
    } else {
        Ok(G2Affine::new_unchecked(f1, f2))
    }
}

const G1_BYTES: usize = 64; // two 32-byte Montgomery-form Fq limbs
const G2_BYTES: usize = 128; // two Fq2

// Keep point-section staging bounded. Whole-key zkeys can contain hundreds of
// MiB in one query; duplicating the complete raw section beside its converted
// affine vector is especially costly in WebAssembly linear memory. Rayon builds
// still convert each bounded batch in parallel.
const POINT_PARSE_CHUNK_BYTES: usize = 8 * 1024 * 1024;

fn deserialize_g1_vec<R: Read>(reader: &mut R, n_vars: usize) -> IoResult<Vec<G1Affine>> {
    deserialize_point_vec(reader, n_vars, G1_BYTES, |encoded| {
        deserialize_g1(&mut &encoded[..])
    })
}

fn deserialize_g2_vec<R: Read>(reader: &mut R, n_vars: usize) -> IoResult<Vec<G2Affine>> {
    deserialize_point_vec(reader, n_vars, G2_BYTES, |encoded| {
        deserialize_g2(&mut &encoded[..])
    })
}

fn deserialize_point_vec<R, P, F>(
    reader: &mut R,
    count: usize,
    encoded_bytes: usize,
    convert: F,
) -> IoResult<Vec<P>>
where
    R: Read,
    P: Send,
    F: Fn(&[u8]) -> IoResult<P> + Sync,
{
    let mut points = Vec::new();
    points
        .try_reserve_exact(count)
        .map_err(|_| SerializationError::InvalidData)?;
    let chunk_points = (POINT_PARSE_CHUNK_BYTES / encoded_bytes).max(1);
    let buffer_len = count
        .min(chunk_points)
        .checked_mul(encoded_bytes)
        .ok_or(SerializationError::InvalidData)?;
    let mut bytes = vec![0_u8; buffer_len];

    let mut remaining = count;
    while remaining != 0 {
        let batch_points = remaining.min(chunk_points);
        let batch_bytes = batch_points
            .checked_mul(encoded_bytes)
            .ok_or(SerializationError::InvalidData)?;
        let batch = &mut bytes[..batch_bytes];
        reader.read_exact(batch)?;

        #[cfg(feature = "parallel")]
        {
            let mut converted = batch
                .par_chunks_exact(encoded_bytes)
                .map(&convert)
                .collect::<IoResult<Vec<_>>>()?;
            points.append(&mut converted);
        }
        #[cfg(not(feature = "parallel"))]
        {
            for encoded in batch.chunks_exact(encoded_bytes) {
                points.push(convert(encoded)?);
            }
        }
        remaining -= batch_points;
    }
    Ok(points)
}

#[cfg(test)]
mod canonical_encoding_tests {
    use super::*;
    use ark_ff::BigInteger;
    use std::io::Cursor;

    #[test]
    fn noncanonical_montgomery_encodings_are_rejected_before_arithmetic() {
        for bytes in [Fq::MODULUS.to_bytes_le(), vec![255; 32]] {
            assert!(deserialize_field(&mut bytes.as_slice()).is_err());
            let mut g1 = vec![0; 64];
            g1[..32].copy_from_slice(&bytes);
            assert!(deserialize_g1(&mut g1.as_slice()).is_err());
            for limb in 0..4 {
                let mut g2 = vec![0; 128];
                g2[limb * 32..(limb + 1) * 32].copy_from_slice(&bytes);
                assert!(deserialize_g2(&mut g2.as_slice()).is_err());
            }
        }
        assert!(deserialize_field_fr(&mut Fr::MODULUS.to_bytes_le().as_slice()).is_err());
        let input = include_bytes!("../testdata/noncanonical-g2.zkey");
        assert!(read_zkey(&mut Cursor::new(input)).is_err());
        #[cfg(feature = "zkey-single-pass")]
        assert!(read_zkey_sequential(&mut Cursor::new(input)).is_err());
    }
}

#[cfg(test)]
mod crs_consistency_tests {
    use std::io::Cursor;

    use ark_bn254::Bn254;
    use ark_ec::AffineRepr;
    use ark_groth16::ProvingKey;

    const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");

    fn key() -> ProvingKey<Bn254> {
        super::read_zkey(&mut Cursor::new(ZKEY))
            .expect("fixture zkey parses")
            .0
    }

    #[test]
    fn the_fixture_key_is_internally_consistent() {
        let pk = key();
        super::validate_proving_key(&pk).expect("every point is valid");
        super::validate_crs_consistency(&pk).expect("the CRS is consistent");
    }

    /// The whole point of this check. Negating a B entry leaves it a perfectly
    /// good curve point in the right subgroup, so point validation sees nothing
    /// wrong - but the G1 and G2 queries no longer encode the same values.
    #[test]
    fn an_inconsistent_b_query_passes_point_validation_and_fails_here() {
        let mut pk = key();
        let index = pk
            .b_g2_query
            .iter()
            .position(|point| !point.is_zero())
            .expect("the fixture has a non-trivial B entry");
        pk.b_g2_query[index] = -pk.b_g2_query[index];

        super::validate_proving_key(&pk).expect("negation keeps every point valid");
        assert!(
            super::validate_crs_consistency(&pk).is_err(),
            "a B query that disagrees across groups must be rejected",
        );
    }

    #[test]
    fn a_delta_that_disagrees_across_groups_is_rejected() {
        let mut pk = key();
        assert_ne!(pk.delta_g1, pk.beta_g1, "the fixture must distinguish them");
        pk.delta_g1 = pk.beta_g1;

        super::validate_proving_key(&pk).expect("beta_g1 is itself a valid point");
        assert!(super::validate_crs_consistency(&pk).is_err());
    }

    #[test]
    fn mismatched_b_query_lengths_are_rejected() {
        let mut pk = key();
        pk.b_g2_query.pop();
        assert!(super::validate_crs_consistency(&pk).is_err());
    }
}

#[cfg(test)]
mod domain_tests {
    use std::io::Cursor;

    const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");

    /// Re-emit the fixture with `domain_size` in its Groth header and the H
    /// query padded with identity points to match, so every section length
    /// still agrees with the header.
    fn with_domain(domain_size: u32) -> Vec<u8> {
        let count = u32::from_le_bytes(ZKEY[8..12].try_into().expect("section count"));
        let mut out = ZKEY[..12].to_vec();
        let mut offset = 12;
        for _ in 0..count {
            let id = u32::from_le_bytes(ZKEY[offset..offset + 4].try_into().expect("section id"));
            let length = u64::from_le_bytes(
                ZKEY[offset + 4..offset + 12]
                    .try_into()
                    .expect("section length"),
            ) as usize;
            let mut body = ZKEY[offset + 12..offset + 12 + length].to_vec();
            match id {
                // n8q, q, n8r, r, n_vars and n_public precede domain_size.
                2 => body[80..84].copy_from_slice(&domain_size.to_le_bytes()),
                9 => body.resize(domain_size as usize * super::G1_BYTES, 0),
                _ => {}
            }
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&(body.len() as u64).to_le_bytes());
            out.extend_from_slice(&body);
            offset += 12 + length;
        }
        out
    }

    /// One constraint and one public input need a four-point domain. A header
    /// claiming eight is internally consistent with its padded H query, but the
    /// prover would only ever use four of those bases.
    #[test]
    fn a_domain_larger_than_the_constraints_need_is_rejected() {
        let (pk, _) = super::read_zkey(&mut Cursor::new(with_domain(4)))
            .expect("re-emitting the fixture's own domain must still parse");
        assert_eq!(pk.h_query.len(), 4);

        let oversized = with_domain(8);
        assert!(super::read_zkey(&mut Cursor::new(&oversized)).is_err());
        #[cfg(feature = "zkey-single-pass")]
        assert!(super::read_zkey_sequential(&mut Cursor::new(&oversized)).is_err());

        use sha2::Digest;
        let pin = sha2::Sha256::digest(&oversized)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(matches!(
            crate::Prover::from_zkey_bytes(&oversized, &pin),
            Err(crate::ProverError::InvalidZkey(
                ark_serialize::SerializationError::InvalidData
            ))
        ));
    }
}

#[cfg(all(test, feature = "zkey-single-pass"))]
mod single_pass_tests {
    use std::io::Cursor;

    use sha2::{Digest, Sha256};

    const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");

    /// The streaming walk and the seeking reader must agree exactly; the walk
    /// additionally returns the digest of what it consumed.
    #[test]
    fn streaming_walk_parses_the_same_key_as_the_seeking_reader() {
        let (expected_key, expected_matrices) =
            super::read_zkey(&mut Cursor::new(ZKEY)).expect("seeking reader parses the fixture");
        let (key, matrices, digest) = super::read_zkey_sequential(&mut Cursor::new(ZKEY))
            .expect("streaming reader parses the fixture");

        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(ZKEY)));
        assert_eq!(key.vk.alpha_g1, expected_key.vk.alpha_g1);
        assert_eq!(key.vk.beta_g2, expected_key.vk.beta_g2);
        assert_eq!(key.vk.gamma_g2, expected_key.vk.gamma_g2);
        assert_eq!(key.vk.delta_g2, expected_key.vk.delta_g2);
        assert_eq!(key.vk.gamma_abc_g1, expected_key.vk.gamma_abc_g1);
        assert_eq!(key.beta_g1, expected_key.beta_g1);
        assert_eq!(key.delta_g1, expected_key.delta_g1);
        assert_eq!(key.a_query, expected_key.a_query);
        assert_eq!(key.b_g1_query, expected_key.b_g1_query);
        assert_eq!(key.b_g2_query, expected_key.b_g2_query);
        assert_eq!(key.l_query, expected_key.l_query);
        assert_eq!(key.h_query, expected_key.h_query);

        assert_eq!(matrices.num_constraints, expected_matrices.num_constraints);
        assert_eq!(
            matrices.num_instance_variables,
            expected_matrices.num_instance_variables
        );
        #[cfg(not(feature = "compact-matrix"))]
        assert_eq!(matrices.matrices, expected_matrices.matrices);
        #[cfg(feature = "compact-matrix")]
        for (actual, expected) in matrices.matrices.iter().zip(&expected_matrices.matrices) {
            assert_eq!(actual.to_arkworks(), expected.to_arkworks());
        }
    }

    /// A truncated artifact must fail rather than digest a short file.
    #[test]
    fn streaming_walk_rejects_a_truncated_artifact() {
        let truncated = &ZKEY[..ZKEY.len() - 64];
        assert!(super::read_zkey_sequential(&mut Cursor::new(truncated)).is_err());
    }

    /// Byte offset of the Groth header's `domain_size` field: section 2's body
    /// starts with n8q, q, n8r, r, n_vars and n_public.
    fn domain_size_offset() -> usize {
        let count = u32::from_le_bytes(ZKEY[8..12].try_into().expect("section count"));
        let mut offset = 12;
        for _ in 0..count {
            let id = u32::from_le_bytes(ZKEY[offset..offset + 4].try_into().expect("section id"));
            let length = u64::from_le_bytes(
                ZKEY[offset + 4..offset + 12]
                    .try_into()
                    .expect("section length"),
            ) as usize;
            if id == 2 {
                return offset + 12 + 4 + 32 + 4 + 32 + 4 + 4;
            }
            offset += 12 + length;
        }
        panic!("fixture has a Groth header");
    }

    /// A header may declare dimensions no artifact of that size could hold. The
    /// streaming walk meets section 4, which allocates from `domain_size`,
    /// before the H query whose length would contradict it, so the dimensions
    /// have to be bounded up front. Either way this must be a rejection and
    /// never an allocation the process cannot satisfy.
    #[test]
    fn streaming_walk_rejects_dimensions_larger_than_the_artifact() {
        for domain_size in [1_u32 << 20, 1_u32 << 31] {
            let mut crafted = ZKEY.to_vec();
            let offset = domain_size_offset();
            crafted[offset..offset + 4].copy_from_slice(&domain_size.to_le_bytes());
            assert!(
                super::read_zkey_sequential(&mut Cursor::new(crafted)).is_err(),
                "domain_size {domain_size} must be rejected",
            );
        }
    }
}

#[cfg(all(test, feature = "compact-matrix"))]
mod compact_parser_tests {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");

    #[test]
    fn first_pass_rejects_an_invalid_matrix_index() {
        let section = section_position(ZKEY, 4);
        let mut bytes = ZKEY.to_vec();
        bytes[section + 4..section + 8].copy_from_slice(&2_u32.to_le_bytes());
        assert!(super::read_zkey(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn second_pass_revalidates_coefficient_indices() {
        let section = section_position(ZKEY, 4) as u64;
        let mut reader = SecondPassMutation {
            cursor: Cursor::new(ZKEY.to_vec()),
            section,
            section_seeks: 0,
            mutation: (section as usize + 4, 2),
        };
        assert!(super::read_zkey(&mut reader).is_err());
        assert_eq!(reader.section_seeks, 2, "fixture must exercise both passes");
    }

    #[test]
    fn second_pass_rejects_changed_row_counts_with_the_same_total_and_last_row() {
        let position = section_position(ZKEY, 2);
        let mut header = super::HeaderGroth::read(&mut Cursor::new(&ZKEY[position..])).unwrap();
        header.domain_size = 8;
        header.n_public = 1;
        // Three retained rows and the public-input marker. Moving the middle
        // record to row zero leaves the total and final row count unchanged.
        let mut bytes = 4_u32.to_le_bytes().to_vec();
        for row in [0_u32, 1, 2, 4] {
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&row.to_le_bytes());
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&[0; 32]);
        }
        let section = super::Section {
            position: 0,
            size: bytes.len(),
        };
        super::parse_compact_matrices(&mut Cursor::new(&bytes), &section, &header).unwrap();
        // Both overflow into the preceding row and underfill from moving to a
        // discarded row must fail, even though the last retained row is full.
        for replacement in [0, 4] {
            let mut reader = SecondPassMutation {
                cursor: Cursor::new(bytes.clone()),
                section: 0,
                section_seeks: 0,
                mutation: (4 + 44 + 4, replacement),
            };
            assert!(super::parse_compact_matrices(&mut reader, &section, &header).is_err());
            assert_eq!(reader.section_seeks, 2);
        }
    }

    #[test]
    fn compact_parse_keeps_coefficient_passes_sequential() {
        let mut reader = RejectRelativeSeek(Cursor::new(ZKEY));
        super::read_zkey(&mut reader).expect("compact fixture should parse without relative seeks");
    }

    fn section_position(bytes: &[u8], wanted: u32) -> usize {
        let sections = u32::from_le_bytes(bytes[8..12].try_into().expect("section count"));
        let mut cursor = 12;
        for _ in 0..sections {
            let id = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().expect("section id"));
            let length = u64::from_le_bytes(
                bytes[cursor + 4..cursor + 12]
                    .try_into()
                    .expect("section length"),
            ) as usize;
            let position = cursor + 12;
            if id == wanted {
                return position;
            }
            cursor = position + length;
        }
        panic!("fixture has no section {wanted}");
    }

    struct SecondPassMutation {
        cursor: Cursor<Vec<u8>>,
        section: u64,
        section_seeks: usize,
        mutation: (usize, u32),
    }

    impl Read for SecondPassMutation {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.cursor.read(buffer)
        }
    }

    impl Seek for SecondPassMutation {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            let new_position = self.cursor.seek(position)?;
            if new_position == self.section {
                self.section_seeks += 1;
                if self.section_seeks == 2 {
                    let (offset, value) = self.mutation;
                    self.cursor.get_mut()[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                }
            }
            Ok(new_position)
        }
    }

    struct RejectRelativeSeek<R>(R);

    impl<R: Read> Read for RejectRelativeSeek<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buffer)
        }
    }

    impl<R: Seek> Seek for RejectRelativeSeek<R> {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            if matches!(position, SeekFrom::Current(32)) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "compact parsing must read rather than seek over coefficients",
                ));
            }
            self.0.seek(position)
        }
    }
}
