//! Reproducible synthetic sweeps for whole-key proof scheduling decisions.
//!
//! This is feature-gated benchmark support, not part of the proving API. It
//! uses Curvy's actual MSM implementation and deterministic BN254 inputs while
//! excluding zkey I/O and witness-map FFTs.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInt, PrimeField};
#[cfg(feature = "compact-matrix")]
use ark_groth16::r1cs_to_qap::evaluate_constraint;
#[cfg(feature = "compact-matrix")]
use ark_relations::utils::matrix::Matrix;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::msm::{adaptive_window_bits, msm_bigint, msm_bigint_with_window};
#[cfg(feature = "compact-matrix")]
use crate::qap::CompactMatrix;

/// The five large query results produced by the outer scheduling sweep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMsmOutput {
    pub h: G1Projective,
    pub l: G1Projective,
    pub a: G1Projective,
    pub b1: G1Projective,
    pub b2: G2Projective,
}

/// Deterministic equal-sized stand-ins for H, L, A, B1, and B2 queries.
pub struct ProofMsmFixture {
    h: Vec<G1Affine>,
    l: Vec<G1Affine>,
    a: Vec<G1Affine>,
    b1: Vec<G1Affine>,
    b2: Vec<G2Affine>,
    h_scalars: Vec<Fr>,
    assignment: Vec<Fr>,
}

impl ProofMsmFixture {
    pub fn new(log_size: u32) -> Self {
        let size = 1usize
            .checked_shl(log_size)
            .expect("benchmark log size must fit usize");
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        let h = vec![g1.mul_bigint([3]).into_affine(); size];
        let l = vec![g1.mul_bigint([5]).into_affine(); size];
        let a = vec![g1.mul_bigint([7]).into_affine(); size];
        let b1 = vec![g1.mul_bigint([11]).into_affine(); size];
        let b2 = vec![g2.mul_bigint([13]).into_affine(); size];
        let h_scalars = deterministic_scalars(size, 0x726f_6f74_2d68_7a31);
        let assignment = deterministic_scalars(size, 0x6173_7369_676e_7631);
        Self {
            h,
            l,
            a,
            b1,
            b2,
            h_scalars,
            assignment,
        }
    }

    pub fn points(&self) -> usize {
        self.assignment.len()
    }

    /// Current strategy: materialize H and shared assignment bigints, then run
    /// the five MSMs one after another.
    pub fn materialized_sequential(&self) -> ProofMsmOutput {
        let h_scalars = to_bigints(&self.h_scalars);
        let assignment = to_bigints(&self.assignment);
        ProofMsmOutput {
            h: msm_bigint::<G1Projective>(&self.h, &h_scalars),
            l: msm_bigint::<G1Projective>(&self.l, &assignment),
            a: msm_bigint::<G1Projective>(&self.a, &assignment),
            b1: msm_bigint::<G1Projective>(&self.b1, &assignment),
            b2: msm_bigint::<G2Projective>(&self.b2, &assignment),
        }
    }

    /// Materialize the same scalar vectors, then expose independent outer MSMs
    /// to the existing Rayon pool. Each MSM still parallelizes its own windows.
    #[cfg(feature = "parallel")]
    pub fn materialized_concurrent(&self) -> ProofMsmOutput {
        let h_scalars = to_bigints(&self.h_scalars);
        let assignment = to_bigints(&self.assignment);
        let ((h, l), (a, (b1, b2))) = rayon::join(
            || {
                rayon::join(
                    || msm_bigint::<G1Projective>(&self.h, &h_scalars),
                    || msm_bigint::<G1Projective>(&self.l, &assignment),
                )
            },
            || {
                rayon::join(
                    || msm_bigint::<G1Projective>(&self.a, &assignment),
                    || {
                        rayon::join(
                            || msm_bigint::<G1Projective>(&self.b1, &assignment),
                            || msm_bigint::<G2Projective>(&self.b2, &assignment),
                        )
                    },
                )
            },
        );
        ProofMsmOutput { h, l, a, b1, b2 }
    }

    /// Bound bigint materialization and reuse each assignment chunk across L,
    /// A, B1, and B2. Fixed full-query windows make this algebraically
    /// identical to the materialized strategy and isolate chunk overhead.
    pub fn chunked_sequential(&self, chunk_points: usize) -> ProofMsmOutput {
        assert!(chunk_points > 0, "chunk size must be non-zero");
        let width = adaptive_window_bits(self.points());
        let mut output = ProofMsmOutput {
            h: G1Projective::default(),
            l: G1Projective::default(),
            a: G1Projective::default(),
            b1: G1Projective::default(),
            b2: G2Projective::default(),
        };

        for (bases, scalars) in self
            .h
            .chunks(chunk_points)
            .zip(self.h_scalars.chunks(chunk_points))
        {
            let scalars = to_bigints(scalars);
            output.h += msm_bigint_with_window::<G1Projective>(bases, &scalars, width);
        }

        for start in (0..self.points()).step_by(chunk_points) {
            let end = (start + chunk_points).min(self.points());
            let scalars = to_bigints(&self.assignment[start..end]);
            output.l +=
                msm_bigint_with_window::<G1Projective>(&self.l[start..end], &scalars, width);
            output.a +=
                msm_bigint_with_window::<G1Projective>(&self.a[start..end], &scalars, width);
            output.b1 +=
                msm_bigint_with_window::<G1Projective>(&self.b1[start..end], &scalars, width);
            output.b2 +=
                msm_bigint_with_window::<G2Projective>(&self.b2[start..end], &scalars, width);
        }
        output
    }
}

/// Sparse-row locality fixture for the compact-matrix prototype.
#[cfg(feature = "compact-matrix")]
pub struct MatrixEvaluationFixture {
    dense: Matrix<Fr>,
    compact: CompactMatrix<Fr>,
    assignment: Vec<Fr>,
}

#[cfg(feature = "compact-matrix")]
impl MatrixEvaluationFixture {
    /// Construct `rows` constraints with one coefficient every `nonzero_stride`
    /// rows. A stride of five approximates the sparse pending-circuit artifact.
    pub fn new(rows: usize, nonzero_stride: usize) -> Self {
        assert!(rows != 0 && nonzero_stride != 0);
        let assignment = deterministic_scalars(1_024, 0x6d61_7472_6978_2d31);
        let mut dense = Vec::with_capacity(rows);
        let mut offsets = Vec::with_capacity(rows + 1);
        let mut coefficients = Vec::with_capacity(rows.div_ceil(nonzero_stride));
        let mut signals = Vec::with_capacity(rows.div_ceil(nonzero_stride));
        offsets.push(0);
        for row in 0..rows {
            let mut combination = Vec::new();
            if row % nonzero_stride == 0 {
                let coefficient = Fr::from((row as u64).wrapping_mul(17).wrapping_add(1));
                let signal = row % assignment.len();
                combination.push((coefficient, signal));
                coefficients.push(coefficient);
                signals.push(signal as u32);
            }
            combination.shrink_to_fit();
            dense.push(combination);
            offsets.push(coefficients.len() as u32);
        }
        let compact = CompactMatrix::from_parts(offsets, coefficients, signals);
        Self {
            dense,
            compact,
            assignment,
        }
    }

    pub fn dense_evaluations(&self) -> Vec<Fr> {
        self.dense
            .par_iter()
            .map(|row| evaluate_constraint(row, &self.assignment))
            .collect()
    }

    pub fn compact_evaluations(&self) -> Vec<Fr> {
        (0..self.compact.num_rows())
            .into_par_iter()
            .map(|row| self.compact.evaluate_row(row, &self.assignment))
            .collect()
    }

    pub fn dense_storage_bytes(&self) -> usize {
        self.dense.capacity() * size_of::<Vec<(Fr, usize)>>()
            + self
                .dense
                .iter()
                .map(|row| row.capacity() * size_of::<(Fr, usize)>())
                .sum::<usize>()
    }

    pub fn compact_storage_bytes(&self) -> usize {
        self.compact.storage_bytes()
    }
}

#[cfg(feature = "parallel")]
fn to_bigints(scalars: &[Fr]) -> Vec<BigInt<4>> {
    scalars
        .par_iter()
        .map(|scalar| scalar.into_bigint())
        .collect()
}

#[cfg(not(feature = "parallel"))]
fn to_bigints(scalars: &[Fr]) -> Vec<BigInt<4>> {
    scalars.iter().map(|scalar| scalar.into_bigint()).collect()
}

fn deterministic_scalars(size: usize, seed: u64) -> Vec<Fr> {
    let mut state = seed;
    (0..size)
        .map(|_| {
            let mut bytes = [0_u8; 32];
            for word in bytes.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                word.copy_from_slice(&state.to_le_bytes());
            }
            Fr::from_le_bytes_mod_order(&bytes)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "compact-matrix")]
    use super::MatrixEvaluationFixture;
    use super::ProofMsmFixture;

    #[test]
    fn schedules_and_chunking_preserve_all_five_msm_results() {
        let fixture = ProofMsmFixture::new(7);
        let expected = fixture.materialized_sequential();
        assert_eq!(fixture.chunked_sequential(17), expected);
        #[cfg(feature = "parallel")]
        assert_eq!(fixture.materialized_concurrent(), expected);
    }

    #[cfg(feature = "compact-matrix")]
    #[test]
    fn compact_and_dense_matrix_evaluation_match() {
        let fixture = MatrixEvaluationFixture::new(1_003, 5);
        assert_eq!(fixture.compact_evaluations(), fixture.dense_evaluations());
        assert!(fixture.compact_storage_bytes() < fixture.dense_storage_bytes());
    }
}
