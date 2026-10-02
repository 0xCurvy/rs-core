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

// Copied from the PoC with its arkworks baselines and alternative layouts
// (step-1 integration); limb code indexes several arrays in lockstep.
#![allow(dead_code, clippy::needless_range_loop, clippy::wrong_self_convention)]

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

#[cfg(feature = "wasm")]
pub(crate) mod self_test;
#[cfg(feature = "sparrow")]
mod sparrow;

use fq2::Fq2Simd;
use kernel::{Phases, Stats};
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
            &mut Phases::default(),
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
            &mut Phases::default(),
        );
        return Some(*downcast::<_, V>(&sum));
    }
    None
}

fn downcast<T: 'static, U: 'static>(value: &T) -> &U {
    (value as &dyn Any)
        .downcast_ref::<U>()
        .expect("SIMD MSM dispatch matched the concrete curve type")
}
