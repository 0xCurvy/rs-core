//! Opt-in (`wasm-simd-fft`, wasm32 + simd128 only): the witness map's BN254
//! Fr transforms on a 4-lane simd128 9x29-bit Montgomery multiply. Prototype
//! from poc/wasm-fft; results are bit-identical to ark-poly (the PoC tests
//! every size 2^3..2^18 against fft/ifft/coset fft and this exact step;
//! `simdFftSelfTest` checks `qap::finish_evaluations` in a
//! `wasm-simd-selftest` build of the shipped code).
//!
//! Each NTT is serial. With `parallel`, the three independent transforms
//! (A, B, C) run concurrently on the host's Rayon pool instead, and only on
//! pools of at most `MAX_WORKERS` threads: ark-poly's parallel FFT keeps
//! scaling past three workers, three serial NTTs do not.
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
use core::arch::wasm32::u32x4_splat;

/// Largest Rayon pool on which the SIMD transforms run. Witness-map
/// transforms (2^18 and 2^19, Chromium 143, Apple M4 Pro) took 0.76-0.77x
/// of ark-poly's parallel time on 2 and 4 workers but 1.35-1.42x on 8.
#[cfg(feature = "parallel")]
pub(crate) const MAX_WORKERS: usize = 4;

/// Whether `WitnessStep::new` may return a step on this thread's pool.
#[cfg(feature = "parallel")]
pub(crate) fn pool_allows_simd() -> bool {
    rayon::current_num_threads() <= MAX_WORKERS
}

#[cfg(not(feature = "parallel"))]
pub(crate) fn pool_allows_simd() -> bool {
    true
}

/// `ifft`, `distribute_powers(g)`, `fft` over one domain, fused: the n^-1 of
/// the inverse transform is folded into the coset scaling.
pub(crate) struct WitnessStep {
    inv: ntt::Plan,
    fwd: ntt::Plan,
    g: Fr,
    size_inv: Fr,
}

impl WitnessStep {
    pub(crate) fn new<F: PrimeField, D: EvaluationDomain<F>>(domain: &D, g: F) -> Option<Self> {
        if TypeId::of::<F>() != TypeId::of::<Fr>()
            || domain.size() < 8
            || !domain.size().is_power_of_two()
            || !domain.coset_offset().is_one()
            || !pool_allows_simd()
        {
            return None;
        }
        let cast = |x: F| -> Fr { *(&x as &dyn Any).downcast_ref::<Fr>().expect("Fr") };
        let n = domain.size();
        let (inv, fwd) = (cast(domain.group_gen_inv()), cast(domain.group_gen()));
        #[cfg(feature = "parallel")]
        let (inv, fwd) = rayon::join(|| ntt::Plan::new(n, inv), || ntt::Plan::new(n, fwd));
        #[cfg(not(feature = "parallel"))]
        let (inv, fwd) = (ntt::Plan::new(n, inv), ntt::Plan::new(n, fwd));
        Some(WitnessStep {
            inv,
            fwd,
            g: cast(g),
            size_inv: cast(domain.size_inv()),
        })
    }

    /// Applies the step to A, B and C: concurrently with `parallel`, else in
    /// turn. Each NTT stays serial.
    pub(crate) fn apply3<F: 'static>(&self, a: &mut Vec<F>, b: &mut Vec<F>, c: &mut Vec<F>) {
        let [a, b, c] = [a, b, c].map(fr_vec);
        #[cfg(feature = "parallel")]
        rayon::join(
            || self.apply(a),
            || rayon::join(|| self.apply(b), || self.apply(c)),
        );
        #[cfg(not(feature = "parallel"))]
        {
            self.apply(a);
            self.apply(b);
            self.apply(c);
        }
    }

    fn apply(&self, v: &mut [Fr]) {
        // Per call, so concurrent steps never share it.
        let mut buf = Vec::new();
        ntt::ntt(&self.inv, v, &mut buf, None, None);
        ntt::ntt(&self.fwd, v, &mut buf, Some((self.g, self.size_inv)), None);
        // The packed copy is witness-derived: wipe it like `qap::WipeOnDrop`
        // (best effort; `black_box` keeps the stores before the free).
        buf.fill([u32x4_splat(0); 9]);
        core::hint::black_box(&buf);
    }
}

// `&mut Vec`, not `&mut [F]`: `Any` downcasts only sized types, and the
// caller's buffers are `Vec`s.
#[allow(clippy::ptr_arg)]
fn fr_vec<F: 'static>(v: &mut Vec<F>) -> &mut Vec<Fr> {
    (v as &mut dyn Any).downcast_mut::<Vec<Fr>>().expect("Fr")
}
