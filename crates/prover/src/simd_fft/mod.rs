//! Opt-in (`wasm-simd-fft`, wasm32 + simd128 only): the witness map's BN254
//! Fr transforms on a 4-lane simd128 9x29-bit Montgomery multiply. Prototype
//! from poc/wasm-fft; results are bit-identical to ark-poly (the PoC tests
//! every size 2^3..2^18 against fft/ifft/coset fft and this exact step).
#![allow(clippy::needless_range_loop, dead_code)]

mod fr29;
#[rustfmt::skip]
#[allow(unused_mut, unused_assignments, clippy::all)]
mod gen_u29;
mod ntt;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use core::any::{Any, TypeId};
use core::cell::RefCell;

/// `ifft`, `distribute_powers(g)`, `fft` over one domain, fused: the n^-1 of
/// the inverse transform is folded into the coset scaling.
pub(crate) struct WitnessStep {
    inv: ntt::Plan,
    fwd: ntt::Plan,
    g: Fr,
    size_inv: Fr,
    buf: RefCell<Vec<ntt::V>>,
}

impl WitnessStep {
    pub(crate) fn new<F: PrimeField, D: EvaluationDomain<F>>(domain: &D, g: F) -> Option<Self> {
        if TypeId::of::<F>() != TypeId::of::<Fr>()
            || domain.size() < 8
            || !domain.size().is_power_of_two()
            || !domain.coset_offset().is_one()
        {
            return None;
        }
        let cast = |x: F| -> Fr { *(&x as &dyn Any).downcast_ref::<Fr>().expect("Fr") };
        let n = domain.size();
        Some(WitnessStep {
            inv: ntt::Plan::new(n, cast(domain.group_gen_inv())),
            fwd: ntt::Plan::new(n, cast(domain.group_gen())),
            g: cast(g),
            size_inv: cast(domain.size_inv()),
            buf: RefCell::new(Vec::new()),
        })
    }

    pub(crate) fn apply<F: 'static>(&self, v: &mut Vec<F>) {
        let v = (v as &mut dyn Any).downcast_mut::<Vec<Fr>>().expect("Fr");
        let mut buf = self.buf.borrow_mut();
        ntt::ntt(&self.inv, v, &mut buf, None, None);
        ntt::ntt(&self.fwd, v, &mut buf, Some((self.g, self.size_inv)), None);
    }
}
