//! Reproducible synthetic sweeps for whole-key proof scheduling decisions.
//!
//! This is feature-gated benchmark support, not part of the proving API. It
//! uses Curvy's actual MSM implementation and deterministic BN254 inputs while
//! excluding zkey I/O and witness-map FFTs. The module only exists with both
//! `bench` and `parallel`, so it has no serial fallbacks.

use std::time::Duration;

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    CurveGroup,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use ark_ff::{BigInt, PrimeField};
#[cfg(feature = "compact-matrix")]
use ark_groth16::r1cs_to_qap::evaluate_constraint;
#[cfg(feature = "compact-matrix")]
use ark_relations::utils::matrix::Matrix;

use rayon::prelude::*;

use crate::msm::{
    Accumulation, adaptive_window_bits, batch_size, msm_bigint, msm_bigint_with_accumulation,
    msm_bigint_with_window, profile_msm_phases, serial_window_bits,
};
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
///
/// Every base is a distinct multiple of its group's generator, within and across
/// queries, so pairing a scalar with the wrong base changes the result.
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
        // Disjoint runs of multiples: query k uses (k * size + 1 + i) * G.
        let start = |query: u64| query * size as u64 + 1;
        let h = distinct_bases::<G1Projective>(start(0), size);
        let l = distinct_bases::<G1Projective>(start(1), size);
        let a = distinct_bases::<G1Projective>(start(2), size);
        let b1 = distinct_bases::<G1Projective>(start(3), size);
        let b2 = distinct_bases::<G2Projective>(start(0), size);
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

/// Bucket accumulator selected by [`MsmFixture`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsmAccumulator {
    /// Arkworks' XYZZ buckets, the accumulator used before batch-affine.
    Xyzz,
    /// Batch-affine buckets, optionally with a batch-size override.
    BatchAffine(Option<usize>),
    /// Whatever the resident MSM selects for this size and width.
    Production,
}

/// Scalar distribution of an [`MsmFixture`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsmScalars {
    /// Uniform canonical Fr integers.
    Uniform,
    /// Witness-like: a quarter each of 0, 1, a random `u64`, and uniform Fr.
    Witness,
    /// Every scalar is 1, so every point lands in one bucket of window 0.
    Ones,
}

/// Time spent in each MSM phase by a serial profiling run.
#[derive(Clone, Copy, Debug, Default)]
pub struct MsmPhases {
    pub recoding: Duration,
    pub accumulation: Duration,
    pub reduction: Duration,
    pub combination: Duration,
}

/// Distinct G1 and G2 bases with one shared scalar vector.
pub struct MsmFixture {
    g1: Vec<G1Affine>,
    g2: Vec<G2Affine>,
    scalars: Vec<BigInt<4>>,
}

impl MsmFixture {
    /// `with_g2 = false` skips the (slower) G2 base generation.
    pub fn new(log_size: u32, scalars: MsmScalars, with_g2: bool) -> Self {
        let size = 1usize
            .checked_shl(log_size)
            .expect("benchmark log size must fit usize");
        let uniform = deterministic_scalars(size, 0x6d73_6d2d_6163_6331);
        let scalars = match scalars {
            MsmScalars::Uniform => uniform,
            MsmScalars::Ones => vec![Fr::from(1_u64); size],
            MsmScalars::Witness => uniform
                .into_iter()
                .enumerate()
                .map(|(index, scalar)| match index % 4 {
                    0 => Fr::from(0_u64),
                    1 => Fr::from(1_u64),
                    2 => Fr::from(scalar.into_bigint().0[0]),
                    _ => scalar,
                })
                .collect(),
        };
        Self {
            g1: distinct_bases::<G1Projective>(1, size),
            g2: if with_g2 {
                distinct_bases::<G2Projective>(1, size)
            } else {
                Vec::new()
            },
            scalars: to_bigints(&scalars),
        }
    }

    pub fn points(&self) -> usize {
        self.scalars.len()
    }

    pub fn g1(&self, accumulator: MsmAccumulator, width: usize) -> G1Projective {
        run_msm::<G1Projective>(&self.g1, &self.scalars, accumulator, width)
    }

    /// Panics if the fixture was built without G2 bases.
    pub fn g2(&self, accumulator: MsmAccumulator, width: usize) -> G2Projective {
        assert_eq!(self.g2.len(), self.scalars.len(), "fixture has no G2 bases");
        run_msm::<G2Projective>(&self.g2, &self.scalars, accumulator, width)
    }

    pub fn profile_g1(&self, accumulator: MsmAccumulator, width: usize) -> MsmPhases {
        profile(&self.g1, &self.scalars, accumulator, width)
    }

    pub fn profile_g2(&self, accumulator: MsmAccumulator, width: usize) -> MsmPhases {
        assert_eq!(self.g2.len(), self.scalars.len(), "fixture has no G2 bases");
        profile(&self.g2, &self.scalars, accumulator, width)
    }
}

/// Window width the resident MSM selects with `parallel`.
pub fn parallel_window_bits(points: usize) -> usize {
    adaptive_window_bits(points)
}

/// Window width the resident MSM selects without `parallel`.
pub fn serial_msm_window_bits(points: usize) -> usize {
    serial_window_bits(points)
}

/// Production batch-affine batch size for a window width.
pub fn batch_affine_batch_size(width: usize) -> usize {
    batch_size(width)
}

fn run_msm<V>(
    bases: &[V::MulBase],
    scalars: &[BigInt<4>],
    accumulator: MsmAccumulator,
    width: usize,
) -> V
where
    V: ark_ec::VariableBaseMSM<ScalarField = Fr>,
{
    match accumulator {
        MsmAccumulator::Xyzz => {
            msm_bigint_with_accumulation::<V>(bases, scalars, width, Accumulation::Xyzz, None)
        }
        MsmAccumulator::BatchAffine(batch) => msm_bigint_with_accumulation::<V>(
            bases,
            scalars,
            width,
            Accumulation::BatchAffine,
            batch,
        ),
        MsmAccumulator::Production => msm_bigint_with_window::<V>(bases, scalars, width),
    }
}

fn profile<P>(
    bases: &[Affine<P>],
    scalars: &[BigInt<4>],
    accumulator: MsmAccumulator,
    width: usize,
) -> MsmPhases
where
    P: SWCurveConfig<ScalarField = Fr>,
{
    let accumulation = match accumulator {
        MsmAccumulator::Xyzz => Accumulation::Xyzz,
        MsmAccumulator::BatchAffine(_) | MsmAccumulator::Production => Accumulation::BatchAffine,
    };
    let (sum, [recoding, accumulation, reduction, combination]) =
        profile_msm_phases::<P>(bases, scalars, width, accumulation);
    let _: Projective<P> = std::hint::black_box(sum);
    MsmPhases {
        recoding,
        accumulation,
        reduction,
        combination,
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

fn to_bigints(scalars: &[Fr]) -> Vec<BigInt<4>> {
    scalars
        .par_iter()
        .map(|scalar| scalar.into_bigint())
        .collect()
}

/// `(start + i) * G` for `i in 0..size`: one scalar multiplication, then
/// incremental additions and a single batch normalization.
fn distinct_bases<G: CurveGroup>(start: u64, size: usize) -> Vec<G::Affine> {
    let generator = G::generator();
    let mut point = generator.mul_bigint([start]);
    let mut points = Vec::with_capacity(size);
    for _ in 0..size {
        points.push(point);
        point += generator;
    }
    G::normalize_batch(&points)
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
    use ark_bn254::{G1Projective, G2Projective};
    use ark_ec::VariableBaseMSM;

    #[cfg(feature = "compact-matrix")]
    use super::MatrixEvaluationFixture;
    use super::{ProofMsmFixture, to_bigints};

    #[test]
    fn schedules_and_chunking_preserve_all_five_msm_results() {
        let fixture = ProofMsmFixture::new(7);
        let bases = fixture.h.iter().chain(&fixture.l).chain(&fixture.a);
        let mut seen = std::collections::HashSet::new();
        assert!(
            bases.chain(&fixture.b1).all(|base| seen.insert(*base)),
            "every G1 base must be distinct"
        );

        // Arkworks' own MSM is independent of Curvy's recoder and scheduler.
        let h_scalars = to_bigints(&fixture.h_scalars);
        let assignment = to_bigints(&fixture.assignment);
        let reference = super::ProofMsmOutput {
            h: G1Projective::msm_bigint(&fixture.h, &h_scalars),
            l: G1Projective::msm_bigint(&fixture.l, &assignment),
            a: G1Projective::msm_bigint(&fixture.a, &assignment),
            b1: G1Projective::msm_bigint(&fixture.b1, &assignment),
            b2: G2Projective::msm_bigint(&fixture.b2, &assignment),
        };
        assert_eq!(fixture.materialized_sequential(), reference);
        // 17 does not divide 128, so the final chunk is also a short one.
        assert_eq!(fixture.chunked_sequential(17), reference);
        assert_eq!(fixture.materialized_concurrent(), reference);
    }

    #[cfg(feature = "compact-matrix")]
    #[test]
    fn compact_and_dense_matrix_evaluation_match() {
        let fixture = MatrixEvaluationFixture::new(1_003, 5);
        assert_eq!(fixture.compact_evaluations(), fixture.dense_evaluations());
        assert!(fixture.compact_storage_bytes() < fixture.dense_storage_bytes());
    }
}
