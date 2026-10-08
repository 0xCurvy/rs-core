//! SPARROW's persistent query buckets in the SIMD kernel's representation
//! (`wasm-simd-msm` with `sparrow`).
//!
//! Each signed window is a [`kernel::AffineBuckets`] with the 4-lane batch
//! application: the schedule of `msm::AffineBuckets` (signed windows,
//! batches of pairwise distinct buckets, deferral, XYZZ overflow for hot
//! buckets) over 29-bit limbs. Buckets and overflow buckets stay in that form
//! across chunks, the chunk buffer holds bases already converted (once, as
//! each point is decoded), and only the window sums return to arkworks
//! (`simd_reduce`).

use ark_bn254::{Fr, g1, g2};
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};

use super::fq2::Fq2Simd;
use super::kernel::{self, Aff};
use super::lanes::Lanes4;
use super::simd_msm::SimdApply;
use super::u29x9::U29x9;
use crate::msm::WindowBuckets;

/// A G1 query window: `U29x9` coordinates.
pub(crate) type SparrowG1 = kernel::AffineBuckets<g1::Config, U29x9, SimdApply<U29x9>>;
/// A G2 query window: `Fq2Simd` coordinates (pairs of `U29x9`).
pub(crate) type SparrowG2 = kernel::AffineBuckets<g2::Config, Fq2Simd, SimdApply<Fq2Simd>>;

impl<C, F> WindowBuckets for kernel::AffineBuckets<C, F, SimdApply<F>>
where
    C: SWCurveConfig<BaseField = F::Ark, ScalarField = Fr>,
    F: Lanes4,
{
    type Curve = C;
    type Base = Aff<F>;

    fn try_new(width: usize) -> Option<Self> {
        kernel::AffineBuckets::try_new(width)
    }

    #[inline]
    fn base(point: &Affine<C>) -> Aff<F> {
        Aff::from_ark(point)
    }

    #[inline]
    fn add_digit(&mut self, digit: i16, base: &Aff<F>) {
        kernel::AffineBuckets::add_digit(self, digit, base);
    }

    fn finish(&mut self) {
        kernel::AffineBuckets::finish(self);
    }

    fn release_scratch(&mut self) {
        kernel::AffineBuckets::release_scratch(self);
    }

    fn window_sum(&self) -> Projective<C> {
        kernel::AffineBuckets::window_sum(self)
    }
}
