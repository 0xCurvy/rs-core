//! Opt-in (`wasm-simd-fft`, wasm32 + simd128 only): the witness map's BN254
//! Fr transforms on a 4-lane simd128 9x29-bit Montgomery multiply. Prototype
//! from poc/wasm-fft; results are bit-identical to ark-poly (the PoC tests
//! every size 2^3..2^18 against fft/ifft/coset fft and this exact step;
//! `simdFftSelfTest` and `simdFftStress` check `qap::finish_evaluations` and
//! the NTTs in a `wasm-simd-selftest` build of the shipped code).
//!
//! The inverse transform, coset scaling and forward transform run fused,
//! depth-first over the packed data (see ntt.rs). With `parallel`, each
//! transform is parallel inside on the host's Rayon pool, so the step scales
//! with the pool: 0.32-0.36x of ark-poly's parallel time on 2, 4, 8 and 13
//! workers (2^18 and 2^19, Chromium 143, Apple M4 Pro), 0.36-0.38x serially.
//! A, B and C are transformed in turn, so only one packed copy (36 bytes per
//! element) is live: running the three concurrently was within 5% on 2-8
//! workers but held three copies (+38 MB WASM heap at 2^19).
#![allow(clippy::needless_range_loop)]

mod fr29;
#[rustfmt::skip]
#[allow(unused_mut, unused_assignments, clippy::all)]
mod gen_u29;
mod ntt;
#[cfg(feature = "wasm-simd-selftest")]
mod self_test;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use core::any::{Any, TypeId};

/// `ifft`, `distribute_powers(g)`, `fft` over one domain, fused: the n^-1 of
/// the inverse transform is folded into the coset scaling.
pub(crate) struct WitnessStep {
    step: ntt::Step,
}

impl WitnessStep {
    pub(crate) fn new<F: PrimeField, D: EvaluationDomain<F>>(domain: &D, g: F) -> Option<Self> {
        Self::with_leaf(domain, g, ntt::LEAF)
    }

    /// [`Self::new`] with an explicit leaf block size (self-test only).
    pub(crate) fn with_leaf<F: PrimeField, D: EvaluationDomain<F>>(
        domain: &D,
        g: F,
        leaf: usize,
    ) -> Option<Self> {
        if TypeId::of::<F>() != TypeId::of::<Fr>()
            || domain.size() < 8
            || !domain.size().is_power_of_two()
            || !domain.coset_offset().is_one()
        {
            return None;
        }
        let cast = |x: F| -> Fr { *(&x as &dyn Any).downcast_ref::<Fr>().expect("Fr") };
        let step = ntt::Step::with_leaf(
            domain.size(),
            cast(domain.group_gen()),
            cast(domain.group_gen_inv()),
            cast(g),
            cast(domain.size_inv()),
            leaf,
        );
        Some(WitnessStep { step })
    }

    /// Applies the step to A, B and C in turn; each transform is parallel
    /// under `parallel`.
    pub(crate) fn apply3<F: 'static>(&self, a: &mut Vec<F>, b: &mut Vec<F>, c: &mut Vec<F>) {
        for v in [a, b, c] {
            self.step.apply(fr_vec(v));
        }
    }
}

// `&mut Vec`, not `&mut [F]`: `Any` downcasts only sized types, and the
// caller's buffers are `Vec`s.
#[allow(clippy::ptr_arg)]
fn fr_vec<F: 'static>(v: &mut Vec<F>) -> &mut Vec<Fr> {
    (v as &mut dyn Any).downcast_mut::<Vec<Fr>>().expect("Fr")
}
