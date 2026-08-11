//! Curvy's parallel Groth16 proof assembly over arkworks' BN254 arithmetic.
//!
//! This module is adapted from `ark-groth16` 0.6.0's `src/prover.rs` and keeps
//! its proof equations. It replaces only the large-MSM scheduling boundary so
//! [`crate::msm`] can use the Rayon pool already initialized by the host, which
//! is required by `wasm-bindgen-rayon`. The upstream code is available from
//! <https://github.com/arkworks-rs/groth16> under MIT OR Apache-2.0; Curvy uses
//! it under MIT. See `THIRD-PARTY-NOTICES.md`.

use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField, Zero};
use ark_groth16::{Proof, ProvingKey, r1cs_to_qap::R1CSToQAP};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::{gr1cs::SynthesisError, utils::matrix::Matrix};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{msm, qap::CircomReduction};

/// Create an ark-groth16 0.6-compatible proof without private Rayon pools.
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

    let h_assignment = into_bigints(h);
    let aux_assignment = to_bigints(&full_assignment[num_inputs..]);
    // Public inputs (except the leading one) followed by private witnesses are
    // exactly `full_assignment[1..]`; retain one conversion for A, B1, and B2.
    let assignment = to_bigints(&full_assignment[1..]);

    let h_acc = msm::msm_bigint::<G1Projective>(&pk.h_query, &h_assignment);
    let l_aux_acc = msm::msm_bigint::<G1Projective>(&pk.l_query, &aux_assignment);
    let r_s_delta_g1 = pk.delta_g1.mul_bigint((r * s).into_bigint());

    let r_g1 = pk.delta_g1.mul_bigint(r.into_bigint());
    let g_a = calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment);
    let s_g_a = g_a.mul_bigint(s.into_bigint());

    // Preserve ark-groth16's branch: B1 is needed only for the r * B1 term in C.
    let g1_b = if r.is_zero() {
        Default::default()
    } else {
        let s_g1 = pk.delta_g1.mul_bigint(s.into_bigint());
        calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment)
    };

    let s_g2 = pk.vk.delta_g2.mul_bigint(s.into_bigint());
    let g2_b = calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment);

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
fn into_bigints(scalars: Vec<Fr>) -> Vec<BigInt<4>> {
    scalars
        .into_par_iter()
        .map(PrimeField::into_bigint)
        .collect()
}

#[cfg(not(feature = "parallel"))]
fn into_bigints(scalars: Vec<Fr>) -> Vec<BigInt<4>> {
    scalars.into_iter().map(PrimeField::into_bigint).collect()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;

    use super::create_proof_with_matrices;
    use crate::qap::CircomReduction;

    const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");

    #[test]
    fn proof_equations_match_ark_groth16_for_fixed_randomizers() {
        let (pk, matrices) = crate::zkey::read_zkey(&mut Cursor::new(ZKEY)).expect("fixture zkey");
        let assignment = [Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)];
        for (r, s) in [
            (Fr::from(17), Fr::from(29)),
            (Fr::from(0), Fr::from(29)),
            (Fr::from(17), Fr::from(0)),
            (Fr::from(0), Fr::from(0)),
        ] {
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
                    &matrices.matrices,
                    matrices.num_instance_variables,
                    matrices.num_constraints,
                    &assignment,
                )
                .expect("arkworks proof");

            assert_eq!(ours, arkworks, "randomizers r={r}, s={s}");
        }
    }
}
