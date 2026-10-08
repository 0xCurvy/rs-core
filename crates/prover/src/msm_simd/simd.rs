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
use crate::msm_simd::u29x9::{MASK, P2, U29x9, W};

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct U29x9x4(pub [v128; 9]);

impl U29x9x4 {
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
