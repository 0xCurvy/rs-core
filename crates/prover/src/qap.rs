// Migrated from the ark-circom 0.6.0 implementation
// (https://github.com/arkworks-rs/circom-compat), licensed MIT OR Apache-2.0.
// The cfg iterator macros retain our portable single-threaded WASM build.
use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_poly::EvaluationDomain;
use ark_relations::{
    gr1cs::{ConstraintSystemRef, SynthesisError},
    utils::matrix::Matrix,
};
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, vec};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A constraint matrix in compressed sparse row (CSR) form.
///
/// The zkey format already bounds row and signal indices to `u32`. Keeping
/// those indices split from field coefficients avoids the padding and one
/// allocation/header per row required by arkworks' nested matrix type.
#[cfg(feature = "compact-matrix")]
pub(crate) struct CompactMatrix<F> {
    row_offsets: Box<[u32]>,
    coefficients: Box<[F]>,
    signals: Box<[u32]>,
}

#[cfg(feature = "compact-matrix")]
impl<F: PrimeField> CompactMatrix<F> {
    pub(crate) fn from_parts(
        row_offsets: Vec<u32>,
        coefficients: Vec<F>,
        signals: Vec<u32>,
    ) -> Self {
        debug_assert_eq!(coefficients.len(), signals.len());
        debug_assert_eq!(
            row_offsets.last().copied().unwrap_or_default() as usize,
            coefficients.len()
        );
        Self {
            row_offsets: row_offsets.into_boxed_slice(),
            coefficients: coefficients.into_boxed_slice(),
            signals: signals.into_boxed_slice(),
        }
    }

    pub(crate) fn num_rows(&self) -> usize {
        self.row_offsets.len().saturating_sub(1)
    }

    #[cfg(feature = "bench")]
    pub(crate) fn storage_bytes(&self) -> usize {
        self.row_offsets.len() * size_of::<u32>()
            + self.coefficients.len() * size_of::<F>()
            + self.signals.len() * size_of::<u32>()
    }

    #[inline]
    pub(crate) fn evaluate_row(&self, row: usize, assignment: &[F]) -> F {
        let start = self.row_offsets[row] as usize;
        let end = self.row_offsets[row + 1] as usize;
        self.coefficients[start..end]
            .iter()
            .zip(&self.signals[start..end])
            .fold(F::zero(), |acc, (&coefficient, &signal)| {
                acc + coefficient * assignment[signal as usize]
            })
    }

    #[cfg(test)]
    pub(crate) fn to_arkworks(&self) -> Matrix<F> {
        (0..self.num_rows())
            .map(|row| {
                let start = self.row_offsets[row] as usize;
                let end = self.row_offsets[row + 1] as usize;
                self.coefficients[start..end]
                    .iter()
                    .zip(&self.signals[start..end])
                    .map(|(&coefficient, &signal)| (coefficient, signal as usize))
                    .collect()
            })
            .collect()
    }
}

/// Implements the witness map used by snarkjs. The arkworks witness map calculates the
/// coefficients of H through computing (AB-C)/Z in the evaluation domain and going back to the
/// coefficients domain. snarkjs instead precomputes the Lagrange form of the powers of tau bases
/// in a domain twice as large and the witness map is computed as the odd coefficients of (AB-C)
/// in that domain. This serves as HZ when computing the C proof element.
pub struct CircomReduction;

fn witness_domain<F: PrimeField, D: EvaluationDomain<F>>(
    num_inputs: usize,
    num_constraints: usize,
    assignment: &[F],
) -> Result<D, SynthesisError> {
    if num_inputs == 0 || num_inputs > assignment.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    let size = num_constraints
        .checked_add(num_inputs)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    size.checked_next_power_of_two()
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let domain = D::new(size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let double_size = domain
        .size()
        .checked_mul(2)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    double_size
        .checked_next_power_of_two()
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let double = D::new(double_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    if double.size() != double_size || double.element(1).square() != domain.element(1) {
        return Err(SynthesisError::PolynomialDegreeTooLarge);
    }
    Ok(domain)
}

fn evaluate_checked<F: PrimeField>(
    row: &[(F, usize)],
    assignment: &[F],
) -> Result<F, SynthesisError> {
    row.iter()
        .try_fold(F::zero(), |sum, (coefficient, signal)| {
            assignment
                .get(*signal)
                .map(|value| sum + *coefficient * value)
                .ok_or(SynthesisError::Unsatisfiable)
        })
}

impl R1CSToQAP for CircomReduction {
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &[Matrix<F>],
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        let zero = F::zero();
        let domain = witness_domain::<F, D>(num_inputs, num_constraints, full_assignment)?;
        let domain_size = domain.size();

        if matrices.len() < 2 || matrices[..2].iter().any(|m| m.len() != num_constraints) {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];

        cfg_iter_mut!(a[..num_constraints])
            .zip(cfg_iter_mut!(b[..num_constraints]))
            .zip(cfg_iter!(&matrices[0]))
            .zip(cfg_iter!(&matrices[1]))
            .try_for_each(|(((a, b), at_i), bt_i)| {
                *a = evaluate_checked(at_i, full_assignment)?;
                *b = evaluate_checked(bt_i, full_assignment)?;
                Ok::<_, SynthesisError>(())
            })?;

        finish_witness_map::<F, D>(a, b, num_inputs, num_constraints, full_assignment)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        _: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        // the usual H query has domain-1 powers. Z has domain powers. So HZ has 2*domain-1 powers.
        let count = max_power
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        count
            .checked_next_power_of_two()
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        // A constant-size circuit still uses the odd point of a two-point
        // domain; D::new(1) would otherwise produce an empty H query.
        let domain = D::new(count.max(2)).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let mut scalars = cfg_into_iter!(0..count)
            .map(|i| delta_inverse * t.pow([i as u64]))
            .collect::<Vec<_>>();
        // generate the lagrange coefficients
        domain.ifft_in_place(&mut scalars);
        Ok(cfg_into_iter!(scalars).skip(1).step_by(2).collect())
    }
}

#[cfg(feature = "compact-matrix")]
pub(crate) fn witness_map_from_compact_matrices<F: PrimeField, D: EvaluationDomain<F>>(
    matrices: &[CompactMatrix<F>; 2],
    num_inputs: usize,
    num_constraints: usize,
    full_assignment: &[F],
) -> Result<Vec<F>, SynthesisError> {
    let zero = F::zero();
    let domain = witness_domain::<F, D>(num_inputs, num_constraints, full_assignment)?;
    let domain_size = domain.size();
    if matrices
        .iter()
        .any(|matrix| matrix.num_rows() != num_constraints)
    {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut a = vec![zero; domain_size];
    let mut b = vec![zero; domain_size];
    cfg_iter_mut!(a[..num_constraints])
        .zip(cfg_iter_mut!(b[..num_constraints]))
        .enumerate()
        .for_each(|(row, (a, b))| {
            *a = matrices[0].evaluate_row(row, full_assignment);
            *b = matrices[1].evaluate_row(row, full_assignment);
        });

    finish_witness_map::<F, D>(a, b, num_inputs, num_constraints, full_assignment)
}

fn finish_witness_map<F: PrimeField, D: EvaluationDomain<F>>(
    mut a: Vec<F>,
    mut b: Vec<F>,
    num_inputs: usize,
    num_constraints: usize,
    full_assignment: &[F],
) -> Result<Vec<F>, SynthesisError> {
    let mut c = Vec::new();
    finish_witness_map_in_place::<F, D>(
        &mut a,
        &mut b,
        &mut c,
        num_inputs,
        num_constraints,
        full_assignment,
    )?;
    Ok(a)
}

fn finish_witness_map_in_place<F: PrimeField, D: EvaluationDomain<F>>(
    a: &mut Vec<F>,
    b: &mut Vec<F>,
    c: &mut Vec<F>,
    num_inputs: usize,
    num_constraints: usize,
    full_assignment: &[F],
) -> Result<(), SynthesisError> {
    let domain = witness_domain::<F, D>(num_inputs, num_constraints, full_assignment)?;
    let start = num_constraints;
    let end = start + num_inputs;
    a[start..end].clone_from_slice(&full_assignment[..num_inputs]);

    finish_evaluations(domain, a, b, c, num_constraints)
}

/// Shared resident/streaming FFT kernel. Callers supply base-domain A/B
/// evaluations, including public-input padding; output replaces A.
pub(crate) fn finish_evaluations<F: PrimeField, D: EvaluationDomain<F>>(
    domain: D,
    a: &mut Vec<F>,
    b: &mut Vec<F>,
    c: &mut Vec<F>,
    num_constraints: usize,
) -> Result<(), SynthesisError> {
    let domain_size = domain.size();
    if a.len() != domain_size || b.len() != domain_size || num_constraints > domain_size {
        return Err(SynthesisError::Unsatisfiable);
    }
    let double_size = domain_size
        .checked_mul(2)
        .and_then(usize::checked_next_power_of_two)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let double = D::new(double_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    if double.size() != 2 * domain_size || double.element(1).square() != domain.element(1) {
        return Err(SynthesisError::PolynomialDegreeTooLarge);
    }

    c.resize(domain_size, F::zero());
    c[num_constraints..].fill(F::zero());
    cfg_iter_mut!(c[..num_constraints])
        .zip(cfg_iter!(a))
        .zip(cfg_iter!(b))
        .for_each(|((c_i, &a), &b)| {
            *c_i = a * b;
        });

    domain.ifft_in_place(a);
    domain.ifft_in_place(b);

    let root_of_unity = double.element(1);
    D::distribute_powers_and_mul_by_const(a, root_of_unity, F::one());
    D::distribute_powers_and_mul_by_const(b, root_of_unity, F::one());

    domain.fft_in_place(a);
    domain.fft_in_place(b);

    // `a` is no longer needed after this product. Reuse its domain-sized
    // allocation instead of asking `mul_polynomials_in_evaluation_domain`
    // for a fourth working vector while `a`, `b`, and `c` are still live.
    // For a 2^24 domain this removes a 512 MiB peak allocation.
    cfg_iter_mut!(a[..])
        .zip(cfg_iter!(b))
        .for_each(|(a_i, b_i)| *a_i *= b_i);

    domain.ifft_in_place(c);
    D::distribute_powers_and_mul_by_const(c, root_of_unity, F::one());
    domain.fft_in_place(c);

    cfg_iter_mut!(a[..])
        .zip(cfg_iter!(c))
        .for_each(|(ab_i, c_i)| *ab_i -= c_i);

    Ok(())
}

#[cfg(feature = "scratch")]
pub(crate) fn witness_map_with_workspace(
    matrices: &[CompactMatrix<ark_bn254::Fr>; 2],
    num_inputs: usize,
    num_constraints: usize,
    assignment: &[ark_bn254::Fr],
    workspace: &mut crate::ProofWorkspace,
) -> Result<(), SynthesisError> {
    use ark_bn254::Fr;
    use ark_poly::GeneralEvaluationDomain;
    let domain =
        witness_domain::<Fr, GeneralEvaluationDomain<Fr>>(num_inputs, num_constraints, assignment)?;
    if matrices.iter().any(|m| m.num_rows() != num_constraints) {
        return Err(SynthesisError::Unsatisfiable);
    }
    workspace.a.resize(domain.size(), Fr::from(0));
    workspace.b.resize(domain.size(), Fr::from(0));
    cfg_iter_mut!(workspace.a[..num_constraints])
        .zip(cfg_iter_mut!(workspace.b[..num_constraints]))
        .enumerate()
        .for_each(|(row, (a, b))| {
            *a = matrices[0].evaluate_row(row, assignment);
            *b = matrices[1].evaluate_row(row, assignment);
        });
    finish_witness_map_in_place::<Fr, GeneralEvaluationDomain<Fr>>(
        &mut workspace.a,
        &mut workspace.b,
        &mut workspace.c,
        num_inputs,
        num_constraints,
        assignment,
    )
}

#[cfg(test)]
mod arithmetic_tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{FftField, Field, UniformRand};
    use ark_poly::GeneralEvaluationDomain as Domain;

    // Independent quadratic interpolation: no ark-poly FFT, witness map,
    // distribute_powers, or production matrix-evaluation helper is used.
    fn interpolate(values: &[Fr], omega: Fr) -> Vec<Fr> {
        let n_inverse = Fr::from(values.len() as u64).inverse().unwrap();
        let omega_inverse = omega.inverse().unwrap();
        (0..values.len())
            .map(|power| {
                let step = omega_inverse.pow([power as u64]);
                let mut factor = Fr::from(1);
                let mut sum = Fr::from(0);
                for value in values {
                    sum += *value * factor;
                    factor *= step;
                }
                sum * n_inverse
            })
            .collect()
    }

    fn horner(coefficients: &[Fr], point: Fr) -> Fr {
        coefficients
            .iter()
            .rev()
            .fold(Fr::from(0), |sum, coefficient| sum * point + coefficient)
    }

    #[test]
    fn qap_matches_independent_interpolation_on_domain_boundaries() {
        let mut rng = ark_std::test_rng();
        let assignment = (0..16).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        for m in [0_usize, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63] {
            for inputs in [1, 2, 4] {
                let n = (m + inputs).next_power_of_two();
                let omega = Fr::get_root_of_unity(n as u64).unwrap();
                let eta = Fr::get_root_of_unity(2 * n as u64).unwrap();
                let matrices: [Matrix<Fr>; 2] = std::array::from_fn(|_| {
                    (0..m)
                        .map(|row| {
                            let signal = row % assignment.len();
                            // Empty rows, duplicate terms, cancellations, and zero coefficients.
                            let coefficient = Fr::rand(&mut rng);
                            if row % 5 == 0 {
                                vec![]
                            } else {
                                vec![
                                    (coefficient, signal),
                                    (-coefficient, signal),
                                    (Fr::from(0), 0),
                                    (Fr::rand(&mut rng), (signal + 1) % assignment.len()),
                                ]
                            }
                        })
                        .collect()
                });
                let mut a = vec![Fr::from(0); n];
                let mut b = a.clone();
                let mut c = a.clone();
                for row in 0..m {
                    for (coefficient, signal) in &matrices[0][row] {
                        a[row] += *coefficient * assignment[*signal];
                    }
                    for (coefficient, signal) in &matrices[1][row] {
                        b[row] += *coefficient * assignment[*signal];
                    }
                    c[row] = a[row] * b[row];
                }
                a[m..m + inputs].copy_from_slice(&assignment[..inputs]);
                let (a, b, c) = (
                    interpolate(&a, omega),
                    interpolate(&b, omega),
                    interpolate(&c, omega),
                );
                let expected = (0..n)
                    .map(|i| {
                        let point = eta * omega.pow([i as u64]);
                        horner(&a, point) * horner(&b, point) - horner(&c, point)
                    })
                    .collect::<Vec<_>>();
                let t = Fr::rand(&mut rng);
                let delta_inverse = Fr::rand(&mut rng);
                let query = CircomReduction::h_query_scalars::<Fr, Domain<Fr>>(
                    n - 1,
                    t,
                    Fr::from(0),
                    delta_inverse,
                )
                .unwrap();
                assert_eq!(query.len(), n);
                let hz: Fr = expected.iter().zip(query).map(|(h, q)| *h * q).sum();
                assert_eq!(
                    hz,
                    (horner(&a, t) * horner(&b, t) - horner(&c, t)) * delta_inverse
                );
                let actual = CircomReduction::witness_map_from_matrices::<Fr, Domain<Fr>>(
                    &matrices,
                    inputs,
                    m,
                    &assignment,
                )
                .unwrap();
                assert_eq!(actual, expected, "m={m}, inputs={inputs}, n={n}");
                #[cfg(feature = "compact-matrix")]
                {
                    let compact = [
                        super::tests::compact(&matrices[0]),
                        super::tests::compact(&matrices[1]),
                    ];
                    assert_eq!(
                        witness_map_from_compact_matrices::<Fr, Domain<Fr>>(
                            &compact,
                            inputs,
                            m,
                            &assignment
                        )
                        .unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn invalid_qap_dimensions_return_errors_without_panicking() {
        let one = [Fr::from(1)];
        for (matrices, inputs, constraints) in [
            (vec![], 1, 0),
            (vec![vec![], vec![]], 0, 0),
            (vec![vec![], vec![]], 2, 0),
            (vec![vec![], vec![]], 1, 1),
            (vec![vec![vec![(Fr::from(1), 1)]], vec![vec![]]], 1, 1),
            (vec![vec![], vec![]], 1, usize::MAX),
            (vec![vec![], vec![]], 1, usize::MAX - 1),
        ] {
            assert!(
                CircomReduction::witness_map_from_matrices::<Fr, Domain<Fr>>(
                    &matrices,
                    inputs,
                    constraints,
                    &one
                )
                .is_err()
            );
        }
        assert!(
            CircomReduction::h_query_scalars::<Fr, Domain<Fr>>(usize::MAX, one[0], one[0], one[0])
                .is_err()
        );
    }
}

#[cfg(all(test, feature = "compact-matrix"))]
mod tests {
    use ark_bn254::Fr;
    use ark_groth16::r1cs_to_qap::{R1CSToQAP, evaluate_constraint};
    use ark_poly::GeneralEvaluationDomain;
    use ark_relations::utils::matrix::Matrix;

    use super::{CircomReduction, CompactMatrix, witness_map_from_compact_matrices};

    pub(super) fn compact(matrix: &Matrix<Fr>) -> CompactMatrix<Fr> {
        let mut offsets = Vec::with_capacity(matrix.len() + 1);
        let mut coefficients = Vec::new();
        let mut signals = Vec::new();
        offsets.push(0);
        for row in matrix {
            for &(coefficient, signal) in row {
                coefficients.push(coefficient);
                signals.push(signal as u32);
            }
            offsets.push(coefficients.len() as u32);
        }
        CompactMatrix::from_parts(offsets, coefficients, signals)
    }

    #[test]
    fn compact_rows_and_h_match_nested() {
        let assignment = (0_u64..16).map(|i| Fr::from(i * i + 3)).collect::<Vec<_>>();
        let mut seed = 0x9e37_79b9_u64;
        let mut next = || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            seed
        };
        let mut dense: [Matrix<Fr>; 2] = [Vec::new(), Vec::new()];
        for matrix in &mut dense {
            for row in 0..64 {
                let mut entries = Vec::new();
                for entry in 0..(row % 6) {
                    // Repeated signal indices deliberately exercise duplicate terms.
                    let signal = (next() as usize + entry / 2) % assignment.len();
                    entries.push((Fr::from(next() | 1), signal));
                }
                matrix.push(entries);
            }
        }
        let compact = [compact(&dense[0]), compact(&dense[1])];

        for matrix in 0..2 {
            assert_eq!(compact[matrix].to_arkworks(), dense[matrix]);
            for (row, dense_row) in dense[matrix].iter().enumerate() {
                assert_eq!(
                    compact[matrix].evaluate_row(row, &assignment),
                    evaluate_constraint(dense_row, &assignment),
                    "matrix {matrix}, row {row}",
                );
            }
        }

        let dense_with_c = [dense[0].clone(), dense[1].clone(), vec![]];
        let expected =
            CircomReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
                &dense_with_c,
                2,
                64,
                &assignment,
            )
            .expect("arkworks-compatible witness map");
        let actual = witness_map_from_compact_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
            &compact,
            2,
            64,
            &assignment,
        )
        .expect("compact witness map");
        assert_eq!(actual, expected);
    }
}
