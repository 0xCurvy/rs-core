//! Differential checks of the SIMD kernel against arkworks'
//! `VariableBaseMSM`, run inside the WASM build (`simdMsmSelfTest`): random
//! inputs at every width 3..=16, and production's adversarial inputs
//! (repeated bases, P and -P, identities, all-equal / zero / one /
//! complementary / edge scalars) with batch sizes 1, 3 and default.

use ark_bn254::Fr;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, PrimeField, UniformRand};
use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};

use super::field::PocField;
use super::fq2::Fq2Simd;
use super::kernel::{self, BatchApply, Stats};
use super::simd_msm::SimdApply;
use super::u29x9::U29x9;

fn run<C, F, A>(bases: &[Affine<C>], scalars: &[BigInt<4>], width: usize, batch: usize)
where
    C: SWCurveConfig<BaseField = F::Ark, ScalarField = Fr>,
    F: PocField,
    A: BatchApply<C, F>,
{
    let expected = Projective::<C>::msm_bigint(bases, scalars);
    let converted = kernel::convert_bases::<C, F>(bases);
    let got = kernel::msm::<C, F, A>(&converted, scalars, width, batch, &mut Stats::default());
    assert_eq!(
        got,
        expected,
        "SIMD MSM width={width} batch={batch} size={}",
        bases.len()
    );
}

fn random_bases<C: SWCurveConfig<ScalarField = Fr>>(
    size: usize,
    rng: &mut impl Rng,
) -> Vec<Affine<C>> {
    let step = Projective::<C>::generator() * Fr::rand(rng);
    let mut point = Projective::<C>::generator() * Fr::rand(rng);
    let mut points = Vec::with_capacity(size);
    for _ in 0..size {
        points.push(point);
        point += step;
    }
    Projective::<C>::normalize_batch(&points)
}

fn cases<C, F, A>(rng: &mut StdRng, size: usize) -> u32
where
    C: SWCurveConfig<BaseField = F::Ark, ScalarField = Fr>,
    F: PocField,
    A: BatchApply<C, F>,
{
    let mut n = 0;
    let random: Vec<BigInt<4>> = (0..size).map(|_| Fr::rand(rng).into_bigint()).collect();
    // Every width on random inputs.
    let sweep = random_bases::<C>(size * 30, rng);
    let sweep_scalars: Vec<BigInt<4>> = (0..size * 30)
        .map(|_| Fr::rand(rng).into_bigint())
        .collect();
    for width in 3..=16 {
        run::<C, F, A>(&sweep, &sweep_scalars, width, kernel::batch_size(width));
        n += 1;
    }
    // Adversarial inputs.
    let p = Projective::<C>::rand(rng).into_affine();
    let q = Projective::<C>::rand(rng).into_affine();
    let modulus_minus_one = {
        let mut v = Fr::MODULUS;
        v.sub_with_borrow(&BigInt::from(1_u64));
        v
    };
    let mut pairs = random.clone();
    let mut complements = random.clone();
    for i in (1..size).step_by(2) {
        pairs[i] = pairs[i - 1];
        complements[i] = (-Fr::from_bigint(random[i - 1]).unwrap()).into_bigint();
    }
    let edges: Vec<BigInt<4>> = (0..size)
        .map(|i| match i % 4 {
            0 => modulus_minus_one,
            1 => BigInt::from(0_u64),
            2 => BigInt::from(1_u64),
            _ => random[i],
        })
        .collect();
    let scalar_sets = [
        random.clone(),
        vec![random[0]; size],
        vec![BigInt::from(1_u64); size],
        vec![BigInt::from(0_u64); size],
        pairs,
        complements,
        edges,
    ];
    let base_sets = [
        vec![p; size],
        (0..size).map(|i| if i % 2 == 0 { p } else { -p }).collect(),
        (0..size)
            .map(|i| [p, p, -p, -p, q, Affine::<C>::identity()][i % 6])
            .collect(),
        vec![Affine::<C>::identity(); size],
        random_bases::<C>(size, rng),
    ];
    for scalars in &scalar_sets {
        for bases in &base_sets {
            for width in [4, 9] {
                for batch in [1, 3, kernel::batch_size(width)] {
                    run::<C, F, A>(bases, scalars, width, batch);
                    n += 1;
                }
            }
        }
    }
    n
}

/// Returns the number of MSMs compared; panics on the first mismatch.
pub(crate) fn self_test(size: usize, seed: u64) -> u32 {
    let mut rng = StdRng::seed_from_u64(seed);
    let g1 = cases::<ark_bn254::g1::Config, U29x9, SimdApply<U29x9>>(&mut rng, size);
    let g2 =
        cases::<ark_bn254::g2::Config, Fq2Simd, SimdApply<Fq2Simd>>(&mut rng, size.div_ceil(2));
    g1 + g2
}
