//! Representation 4 (WASM only): the 9x29 representation, four elements at a
//! time with simd128. `U29x9x4.0[i]` holds limb `i` of four independent
//! elements in its four u32 lanes ("limb-sliced"). One
//! `i64x2.extmul_{low,high}_i32x4_u` pair yields four 29x29 -> 58-bit
//! products, so a 4-way multiplication issues 162 * 2 = 324 vector multiplies
//! instead of 4 * 162 = 648 scalar ones. The accumulator bounds are exactly
//! those of `u29x9` (per lane), so every input `u29x9` accepts is accepted
//! here, and results are identical lane by lane.
//!
//! On arm64, V8 lowers extmul_low/high to UMULL/UMULL2, i64x2.add to ADD.2D
//! and the [0, 2, 4, 6] i32x4 shuffle to UZP1.

use core::arch::wasm32::*;

pub use crate::msm_simd::gen_u29::{mul4, sqr4};
use crate::msm_simd::u29x9::{MASK, MU, P, P2, U29x9, W};

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct U29x9x4(pub [v128; 9]);

impl U29x9x4 {
    #[inline(always)]
    pub fn zero() -> Self {
        U29x9x4([u32x4_splat(0); 9])
    }

    /// Transpose four elements into limb-sliced form.
    #[inline(always)]
    pub fn pack(e: [&U29x9; 4]) -> Self {
        let mut v = [u32x4_splat(0); 9];
        for (i, limb) in v.iter_mut().enumerate() {
            *limb = u32x4(e[0].0[i], e[1].0[i], e[2].0[i], e[3].0[i]);
        }
        U29x9x4(v)
    }

    #[inline(always)]
    pub fn unpack(&self) -> [U29x9; 4] {
        let mut out = [U29x9([0; 9]); 4];
        for i in 0..9 {
            let v = self.0[i];
            out[0].0[i] = u32x4_extract_lane::<0>(v);
            out[1].0[i] = u32x4_extract_lane::<1>(v);
            out[2].0[i] = u32x4_extract_lane::<2>(v);
            out[3].0[i] = u32x4_extract_lane::<3>(v);
        }
        out
    }
}

/// Low 32 bits of the four u64 lanes of (lo, hi), as one u32x4.
#[inline(always)]
fn narrow(lo: v128, hi: v128) -> v128 {
    i32x4_shuffle::<0, 2, 4, 6>(lo, hi)
}

#[inline(always)]
fn normalize4(lo: &[v128; 9], hi: &[v128; 9]) -> [v128; 9] {
    let mask64 = u64x2_splat(MASK as u64);
    let mut out = [u32x4_splat(0); 9];
    let (mut clo, mut chi) = (u64x2_splat(0), u64x2_splat(0));
    for j in 0..9 {
        let vlo = u64x2_add(lo[j], clo);
        let vhi = u64x2_add(hi[j], chi);
        clo = u64x2_shr(vlo, W);
        chi = u64x2_shr(vhi, W);
        out[j] = narrow(v128_and(vlo, mask64), v128_and(vhi, mask64));
    }
    out
}

/// Loop form (reference for the generated, fully unrolled [`mul4`]).
#[inline(always)]
pub fn mul4_ref(a: &[v128; 9], b: &[v128; 9]) -> [v128; 9] {
    let mu = u32x4_splat(MU);
    let mask = u32x4_splat(MASK);
    let mut lo = [u64x2_splat(0); 9];
    let mut hi = [u64x2_splat(0); 9];
    for i in 0..9 {
        let ai = a[i];
        for j in 0..9 {
            lo[j] = u64x2_add(lo[j], u64x2_extmul_low_u32x4(ai, b[j]));
            hi[j] = u64x2_add(hi[j], u64x2_extmul_high_u32x4(ai, b[j]));
        }
        let q = v128_and(i32x4_mul(narrow(lo[0], hi[0]), mu), mask);
        for j in 0..9 {
            let pj = u32x4_splat(P[j]);
            lo[j] = u64x2_add(lo[j], u64x2_extmul_low_u32x4(q, pj));
            hi[j] = u64x2_add(hi[j], u64x2_extmul_high_u32x4(q, pj));
        }
        let (clo, chi) = (u64x2_shr(lo[0], W), u64x2_shr(hi[0], W));
        for j in 0..8 {
            lo[j] = lo[j + 1];
            hi[j] = hi[j + 1];
        }
        lo[8] = u64x2_splat(0);
        hi[8] = u64x2_splat(0);
        lo[0] = u64x2_add(lo[0], clo);
        hi[0] = u64x2_add(hi[0], chi);
    }
    normalize4(&lo, &hi)
}

/// Loop form (reference for the generated [`sqr4`]).
#[inline(always)]
pub fn sqr4_ref(a: &[v128; 9]) -> [v128; 9] {
    let mu = u32x4_splat(MU);
    let mask = u32x4_splat(MASK);
    let mut lo = [u64x2_splat(0); 18];
    let mut hi = [u64x2_splat(0); 18];
    for i in 0..9 {
        for j in (i + 1)..9 {
            lo[i + j] = u64x2_add(lo[i + j], u64x2_extmul_low_u32x4(a[i], a[j]));
            hi[i + j] = u64x2_add(hi[i + j], u64x2_extmul_high_u32x4(a[i], a[j]));
        }
    }
    for k in 1..16 {
        lo[k] = u64x2_shl(lo[k], 1);
        hi[k] = u64x2_shl(hi[k], 1);
    }
    for i in 0..9 {
        lo[2 * i] = u64x2_add(lo[2 * i], u64x2_extmul_low_u32x4(a[i], a[i]));
        hi[2 * i] = u64x2_add(hi[2 * i], u64x2_extmul_high_u32x4(a[i], a[i]));
    }
    for i in 0..9 {
        let q = v128_and(i32x4_mul(narrow(lo[i], hi[i]), mu), mask);
        for j in 0..9 {
            let pj = u32x4_splat(P[j]);
            lo[i + j] = u64x2_add(lo[i + j], u64x2_extmul_low_u32x4(q, pj));
            hi[i + j] = u64x2_add(hi[i + j], u64x2_extmul_high_u32x4(q, pj));
        }
        lo[i + 1] = u64x2_add(lo[i + 1], u64x2_shr(lo[i], W));
        hi[i + 1] = u64x2_add(hi[i + 1], u64x2_shr(hi[i], W));
    }
    let mut tlo = [u64x2_splat(0); 9];
    let mut thi = [u64x2_splat(0); 9];
    tlo.copy_from_slice(&lo[9..18]);
    thi.copy_from_slice(&hi[9..18]);
    normalize4(&tlo, &thi)
}

/// `a - m` lane-wise where `a >= m`, else `a`; limbs normalized.
#[inline(always)]
fn sub_if_geq4(a: &[v128; 9], m: &[u32; 9]) -> [v128; 9] {
    let mask = u32x4_splat(MASK);
    let mut d = [u32x4_splat(0); 9];
    let mut borrow = i32x4_splat(0);
    for i in 0..9 {
        let v = i32x4_add(i32x4_sub(a[i], u32x4_splat(m[i])), borrow);
        d[i] = v128_and(v, mask);
        borrow = i32x4_shr(v, W);
    }
    // borrow lane = -1 where a < m: keep a there.
    let mut r = [u32x4_splat(0); 9];
    for i in 0..9 {
        r[i] = v128_bitselect(a[i], d[i], borrow);
    }
    r
}

#[inline(always)]
pub fn add4(a: &[v128; 9], b: &[v128; 9]) -> [v128; 9] {
    let mask = u32x4_splat(MASK);
    let mut s = [u32x4_splat(0); 9];
    let mut carry = u32x4_splat(0);
    for i in 0..9 {
        let v = u32x4_add(u32x4_add(a[i], b[i]), carry);
        s[i] = v128_and(v, mask);
        carry = u32x4_shr(v, W);
    }
    sub_if_geq4(&s, &P2)
}

#[inline(always)]
pub fn sub4(a: &[v128; 9], b: &[v128; 9]) -> [v128; 9] {
    let mask = u32x4_splat(MASK);
    let mut d = [u32x4_splat(0); 9];
    let mut borrow = i32x4_splat(0);
    for i in 0..9 {
        let v = i32x4_add(i32x4_sub(a[i], b[i]), borrow);
        d[i] = v128_and(v, mask);
        borrow = i32x4_shr(v, W);
    }
    let mut carry = u32x4_splat(0);
    for i in 0..9 {
        let v = u32x4_add(u32x4_add(d[i], v128_and(u32x4_splat(P2[i]), borrow)), carry);
        d[i] = v128_and(v, mask);
        carry = u32x4_shr(v, W);
    }
    d
}
