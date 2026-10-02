//! Opt-in (`wasm-simd-msm`) batch-affine MSM for portable WASM builds with
//! simd128: the arithmetic from `poc/wasm-field` (see its README for the
//! design, bounds argument and measurements).
//!
//! BN254 Fq uses nine unsaturated 29-bit limbs; four independent bucket
//! additions run in simd128 lanes (`i64x2.extmul_{low,high}_i32x4_u`), so
//! each batch keeps four Montgomery-trick chains that share one inversion.
//! G2 uses Fq2 over the same base (three 4-lane products per four Fq2
//! products). Scheduling (distinct buckets per batch, deferral, XYZZ overflow
//! for hot buckets) is the same algorithm as `msm::AffineBuckets`, and the
//! running-sum reduction runs four bucket segments in lanes. Bases are
//! converted from arkworks per call; scalars and results stay arkworks types.
//! Under `sparrow`, SPARROW's persistent query buckets use the same kernel
//! (`sparrow.rs`): they stay in this representation across chunks, and each
//! base is converted once, as it is decoded.
//!
//! Only compiled for `wasm32` with `simd128`; every other build uses `msm.rs`
//! unchanged. Under `parallel` (threaded WASM) windows run on the host's
//! Rayon pool, as in `msm.rs`.

// Limb code indexes several arrays in lockstep.
#![allow(clippy::needless_range_loop, clippy::wrong_self_convention)]

use std::any::{Any, TypeId};

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective, g1, g2};
use ark_ec::VariableBaseMSM;
use ark_ff::BigInt;

mod field;
mod fq2;
#[rustfmt::skip]
mod gen_u29;
mod kernel;
mod lanes;
mod simd;
mod simd_msm;
mod simd_reduce;
mod u29x9;

#[cfg(feature = "wasm-simd-selftest")]
pub(crate) mod self_test;
#[cfg(feature = "sparrow")]
mod sparrow;

use fq2::Fq2Simd;
use kernel::Stats;
use simd_msm::SimdApply;
use u29x9::U29x9;

#[cfg(feature = "sparrow")]
pub(crate) use sparrow::{SparrowG1, SparrowG2};

/// Run the SIMD kernel when `V` is BN254 G1 or G2; `None` otherwise.
pub(crate) fn try_msm<V>(
    bases: &[V::MulBase],
    scalars: &[BigInt<4>],
    width: usize,
    batch: usize,
) -> Option<V>
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    let size = bases.len().min(scalars.len());
    let (bases, scalars) = (&bases[..size], &scalars[..size]);
    if TypeId::of::<V>() == TypeId::of::<G1Projective>() {
        let converted: Vec<kernel::Aff<U29x9>> = bases
            .iter()
            .map(|b| kernel::Aff::from_ark(downcast::<_, G1Affine>(b)))
            .collect();
        let sum = kernel::msm::<g1::Config, U29x9, SimdApply<U29x9>>(
            &converted,
            scalars,
            width,
            batch,
            &mut Stats::default(),
        );
        return Some(*downcast::<_, V>(&sum));
    }
    if TypeId::of::<V>() == TypeId::of::<G2Projective>() {
        let converted: Vec<kernel::Aff<Fq2Simd>> = bases
            .iter()
            .map(|b| kernel::Aff::from_ark(downcast::<_, G2Affine>(b)))
            .collect();
        let sum = kernel::msm::<g2::Config, Fq2Simd, SimdApply<Fq2Simd>>(
            &converted,
            scalars,
            width,
            batch,
            &mut Stats::default(),
        );
        return Some(*downcast::<_, V>(&sum));
    }
    None
}

/// Bucket count and batch size of [`try_sum`]'s window: round-robin digits
/// over 512 buckets keep every batch of 128 on distinct buckets.
const SUM_WIDTH: usize = 10;
const SUM_BATCH: usize = 128;
/// Points per Rayon task in [`try_sum`].
#[cfg(feature = "parallel")]
const SUM_TASK_POINTS: usize = 16_384;

/// Sum of the bases whose scalar is one, when `V` is BN254 G1 or G2;
/// `None` otherwise. The bases are converted as they are read and spread
/// round-robin over one window's buckets, so the additions are
/// batch-affine with one inversion per batch (instead of all landing in
/// one hot bucket), and the buckets are then added up.
pub(crate) fn try_sum<V>(bases: &[V::MulBase], scalars: &[BigInt<4>]) -> Option<V>
where
    V: VariableBaseMSM<ScalarField = Fr>,
{
    if TypeId::of::<V>() == TypeId::of::<G1Projective>() {
        let sum = sum_ones::<g1::Config, U29x9, _>(bases, scalars, |b| downcast::<_, G1Affine>(b));
        return Some(*downcast::<_, V>(&sum));
    }
    if TypeId::of::<V>() == TypeId::of::<G2Projective>() {
        let sum =
            sum_ones::<g2::Config, Fq2Simd, _>(bases, scalars, |b| downcast::<_, G2Affine>(b));
        return Some(*downcast::<_, V>(&sum));
    }
    None
}

fn sum_ones<C, F, B>(
    bases: &[B],
    scalars: &[BigInt<4>],
    affine: impl Fn(&B) -> &ark_ec::short_weierstrass::Affine<C> + Sync,
) -> ark_ec::short_weierstrass::Projective<C>
where
    C: ark_ec::short_weierstrass::SWCurveConfig<BaseField = F::Ark>,
    F: lanes::Lanes4,
    B: Sync,
{
    const ONE: BigInt<4> = BigInt([1, 0, 0, 0]);
    let part = |bases: &[B], scalars: &[BigInt<4>]| {
        let mut window =
            kernel::AffineBuckets::<C, F, SimdApply<F>>::with_batch_size(SUM_WIDTH, SUM_BATCH);
        let buckets = 1_usize << (SUM_WIDTH - 1);
        let mut next = 0;
        for (base, scalar) in bases.iter().zip(scalars) {
            if *scalar == ONE {
                window.add_digit(
                    (next % buckets) as i16 + 1,
                    &kernel::Aff::from_ark(affine(base)),
                );
                next += 1;
            }
        }
        window.finish();
        window.bucket_total()
    };
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        bases
            .par_chunks(SUM_TASK_POINTS)
            .zip(scalars.par_chunks(SUM_TASK_POINTS))
            .map(|(bases, scalars)| part(bases, scalars))
            .reduce(
                ark_ec::short_weierstrass::Projective::<C>::default,
                |a, b| a + b,
            )
    }
    #[cfg(not(feature = "parallel"))]
    part(bases, scalars)
}

fn downcast<T: 'static, U: 'static>(value: &T) -> &U {
    (value as &dyn Any)
        .downcast_ref::<U>()
        .expect("SIMD MSM dispatch matched the concrete curve type")
}
