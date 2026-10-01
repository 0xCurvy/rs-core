//! Curvy's Groth16 proof assembly over arkworks' BN254 arithmetic.
//!
//! This module is adapted from `ark-groth16` 0.6.0's `src/prover.rs` and keeps
//! its proof equations. It replaces only the MSM boundary: [`crate::msm`] uses
//! batch-affine buckets for large BN254 queries in every build, and under
//! `parallel` runs on the Rayon pool already initialized by the host, which is
//! required by `wasm-bindgen-rayon`. The upstream code is available from
//! <https://github.com/arkworks-rs/groth16> under MIT OR Apache-2.0; Curvy uses
//! it under MIT. See `THIRD-PARTY-NOTICES.md`.

use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField, Zero};
#[cfg(not(feature = "compact-matrix"))]
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_groth16::{Proof, ProvingKey};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::gr1cs::SynthesisError;
#[cfg(not(feature = "compact-matrix"))]
use ark_relations::utils::matrix::Matrix;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::msm;
#[cfg(not(feature = "compact-matrix"))]
use crate::qap::CircomReduction;
use crate::qap::WipeOnDrop;
#[cfg(feature = "compact-matrix")]
use crate::qap::{CompactMatrix, witness_map_from_compact_matrices};

/// Create an ark-groth16 0.6-compatible proof without private Rayon pools.
#[cfg(not(feature = "compact-matrix"))]
pub(crate) fn create_proof_with_matrices(
    pk: &ProvingKey<Bn254>,
    r: Fr,
    s: Fr,
    matrices: &[Matrix<Fr>],
    num_inputs: usize,
    num_constraints: usize,
    full_assignment: &[Fr],
) -> Result<Proof<Bn254>, SynthesisError> {
    let h = CircomReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        matrices,
        num_inputs,
        num_constraints,
        full_assignment,
    )?;

    create_proof_from_h(pk, r, s, h, num_inputs, full_assignment)
}

/// Create a proof while retaining constraint matrices in compact CSR form.
#[cfg(feature = "compact-matrix")]
pub(crate) fn create_proof_with_compact_matrices(
    pk: &ProvingKey<Bn254>,
    r: Fr,
    s: Fr,
    matrices: &[CompactMatrix<Fr>; 2],
    num_inputs: usize,
    num_constraints: usize,
    full_assignment: &[Fr],
) -> Result<Proof<Bn254>, SynthesisError> {
    let h = witness_map_from_compact_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        matrices,
        num_inputs,
        num_constraints,
        full_assignment,
    )?;

    create_proof_from_h(pk, r, s, h, num_inputs, full_assignment)
}

fn create_proof_from_h(
    pk: &ProvingKey<Bn254>,
    r: Fr,
    s: Fr,
    h: Vec<Fr>,
    num_inputs: usize,
    full_assignment: &[Fr],
) -> Result<Proof<Bn254>, SynthesisError> {
    // H and both scalar conversions are derived from the witness, so each is
    // wiped when dropped (best effort; see `WipeOnDrop`).
    let h_assignment = into_bigints(h);
    // Public inputs (except the leading one) followed by private witnesses are
    // exactly `full_assignment[1..]`; retain one conversion for A, B1, B2, and
    // L. The L query starts where the private-witness suffix starts in this
    // shared representation, avoiding a second full copy of those scalars.
    let assignment = WipeOnDrop(to_bigints(&full_assignment[1..]));
    assemble_proof(pk, r, s, &h_assignment, &assignment, num_inputs)
}

fn assemble_proof(
    pk: &ProvingKey<Bn254>,
    r: Fr,
    s: Fr,
    h_assignment: &[BigInt<4>],
    assignment: &[BigInt<4>],
    num_inputs: usize,
) -> Result<Proof<Bn254>, SynthesisError> {
    let aux_assignment = &assignment[num_inputs.saturating_sub(1)..];

    let h_acc = msm::msm_bigint::<G1Projective>(&pk.h_query, h_assignment);
    let l_aux_acc = msm::msm_bigint::<G1Projective>(&pk.l_query, aux_assignment);
    let r_s_delta_g1 = pk.delta_g1.mul_bigint((r * s).into_bigint());

    let r_g1 = pk.delta_g1.mul_bigint(r.into_bigint());
    let g_a = calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, assignment);
    let s_g_a = g_a.mul_bigint(s.into_bigint());

    // Preserve ark-groth16's branch: B1 is needed only for the r * B1 term in C.
    let g1_b = if r.is_zero() {
        Default::default()
    } else {
        let s_g1 = pk.delta_g1.mul_bigint(s.into_bigint());
        calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, assignment)
    };

    let s_g2 = pk.vk.delta_g2.mul_bigint(s.into_bigint());
    let g2_b = calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, assignment);

    let mut g_c = s_g_a;
    g_c += g1_b.mul_bigint(r.into_bigint());
    g_c -= &r_s_delta_g1;
    g_c += &l_aux_acc;
    g_c += &h_acc;

    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

fn calculate_coeff<G, V>(initial: V, query: &[G], vk_parameter: G, assignment: &[BigInt<4>]) -> V
where
    G: AffineRepr<ScalarField = Fr, Group = V> + Send + Sync,
    V: VariableBaseMSM<ScalarField = Fr, MulBase = G> + Send + Sync,
{
    // Authenticated zkeys are dimension-checked while parsing, so A/B queries
    // always contain the leading constant coefficient.
    let (constant, linear_query) = query
        .split_first()
        .expect("validated Groth16 query must contain its constant coefficient");
    let linear = msm::msm_bigint::<V>(linear_query, assignment);

    let mut result = initial;
    result += constant;
    result += &linear;
    result += &vk_parameter;
    result
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

#[cfg(feature = "parallel")]
fn into_bigints(scalars: Vec<Fr>) -> WipeOnDrop<BigInt<4>> {
    // Wipe the field form as soon as its integer copy exists.
    let scalars = WipeOnDrop(scalars);
    WipeOnDrop(to_bigints(&scalars))
}

#[cfg(not(feature = "parallel"))]
fn into_bigints(scalars: Vec<Fr>) -> WipeOnDrop<BigInt<4>> {
    // std collects this same-layout `map` in place, so each field element is
    // overwritten by its integer form rather than left in a freed buffer.
    WipeOnDrop(scalars.into_iter().map(PrimeField::into_bigint).collect())
}

#[cfg(feature = "scratch")]
pub(crate) fn create_proof_with_workspace(
    prover: &crate::Prover,
    r: Fr,
    s: Fr,
    full_assignment: &[Fr],
    workspace: &mut crate::ProofWorkspace,
) -> Result<Proof<Bn254>, SynthesisError> {
    crate::qap::witness_map_with_workspace(
        &prover.matrices.matrices,
        prover.matrices.num_instance_variables,
        prover.matrices.num_constraints,
        full_assignment,
        workspace,
    )?;
    workspace.h.resize(workspace.a.len(), BigInt::default());
    workspace
        .assignment
        .resize(full_assignment.len() - 1, BigInt::default());
    ark_std::cfg_iter_mut!(workspace.h)
        .zip(ark_std::cfg_iter!(workspace.a))
        .for_each(|(out, scalar)| *out = scalar.into_bigint());
    ark_std::cfg_iter_mut!(workspace.assignment)
        .zip(ark_std::cfg_iter!(&full_assignment[1..]))
        .for_each(|(out, scalar)| *out = scalar.into_bigint());
    assemble_proof(
        &prover.pk,
        r,
        s,
        &workspace.h,
        &workspace.assignment,
        prover.matrices.num_instance_variables,
    )
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;

    #[cfg(feature = "compact-matrix")]
    use super::create_proof_with_compact_matrices;
    #[cfg(not(feature = "compact-matrix"))]
    use super::create_proof_with_matrices;
    use crate::qap::CircomReduction;

    const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");

    #[test]
    fn proof_equations_match_ark_groth16_for_fixed_randomizers() {
        let (pk, matrices) = crate::zkey::read_zkey(&mut Cursor::new(ZKEY)).expect("fixture zkey");
        let assignment = [Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)];
        #[cfg(feature = "compact-matrix")]
        let arkworks_matrices = &[
            matrices.matrices[0].to_arkworks(),
            matrices.matrices[1].to_arkworks(),
            vec![],
        ][..];
        #[cfg(not(feature = "compact-matrix"))]
        let arkworks_matrices = &matrices.matrices[..];
        for (r, s) in [
            (Fr::from(17), Fr::from(29)),
            (Fr::from(0), Fr::from(29)),
            (Fr::from(17), Fr::from(0)),
            (Fr::from(0), Fr::from(0)),
        ] {
            #[cfg(feature = "compact-matrix")]
            let ours = create_proof_with_compact_matrices(
                &pk,
                r,
                s,
                &matrices.matrices,
                matrices.num_instance_variables,
                matrices.num_constraints,
                &assignment,
            )
            .expect("Curvy proof");
            #[cfg(not(feature = "compact-matrix"))]
            let ours = create_proof_with_matrices(
                &pk,
                r,
                s,
                &matrices.matrices,
                matrices.num_instance_variables,
                matrices.num_constraints,
                &assignment,
            )
            .expect("Curvy proof");
            let arkworks =
                Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
                    &pk,
                    r,
                    s,
                    arkworks_matrices,
                    matrices.num_instance_variables,
                    matrices.num_constraints,
                    &assignment,
                )
                .expect("arkworks proof");

            assert_eq!(ours, arkworks, "randomizers r={r}, s={s}");
            #[cfg(feature = "scratch")]
            {
                let prover = crate::Prover::from_zkey_bytes(
                    ZKEY,
                    "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f",
                )
                .unwrap();
                let mut workspace = crate::ProofWorkspace::new(1024 * 1024);
                let reused =
                    super::create_proof_with_workspace(&prover, r, s, &assignment, &mut workspace)
                        .unwrap();
                assert_eq!(reused, arkworks, "workspace randomizers r={r}, s={s}");
            }
        }
    }
}
