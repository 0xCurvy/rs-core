//! Four-lane (simd128) vectors of a field representation, so the SIMD batch
//! application and reduction are written once for G1 (`U29x9`, one
//! `U29x9x4`) and G2 (`Fq2Simd`, a pair of `U29x9x4`: lane `l` of `c0` and
//! of `c1` is one Fq2 element). WASM only.

use core::arch::wasm32::*;

use crate::msm_simd::field::PocField;
use crate::msm_simd::fq2::Fq2Simd;
use crate::msm_simd::simd::{self, U29x9x4};
use crate::msm_simd::u29x9::{P, U29x9};

pub trait Lanes4: PocField {
    type V: Copy;
    fn pack(e: &[Self; 4]) -> Self::V;
    fn unpack(v: &Self::V) -> [Self; 4];
    fn mul4(a: &Self::V, b: &Self::V) -> Self::V;
    fn sqr4(a: &Self::V) -> Self::V;
    fn add4(a: &Self::V, b: &Self::V) -> Self::V;
    fn sub4(a: &Self::V, b: &Self::V) -> Self::V;
    /// All-ones in lanes whose value is 0 (mod p).
    fn zero_lanes(v: &Self::V) -> v128;
    /// `a` in lanes where `mask` is all-ones, else `b`.
    fn select(a: &Self::V, b: &Self::V, mask: v128) -> Self::V;

    fn get(v: &Self::V, lane: usize) -> Self {
        Self::unpack(v)[lane]
    }
    fn set(v: &mut Self::V, lane: usize, e: &Self) {
        let mut all = Self::unpack(v);
        all[lane] = *e;
        *v = Self::pack(&all);
    }
}

// Out of line on purpose: inlining many ~700-instruction bodies into one
// kernel function measured much slower under V8 (register allocation).
#[inline(never)]
fn mul4_call(a: &[v128; 9], b: &[v128; 9]) -> [v128; 9] {
    simd::mul4(a, b)
}

#[inline(never)]
fn sqr4_call(a: &[v128; 9]) -> [v128; 9] {
    simd::sqr4(a)
}

fn zero_lanes_base(v: &[v128; 9]) -> v128 {
    let (mut zero, mut is_p) = (u32x4_splat(!0), u32x4_splat(!0));
    for i in 0..9 {
        zero = v128_and(zero, i32x4_eq(v[i], u32x4_splat(0)));
        is_p = v128_and(is_p, i32x4_eq(v[i], u32x4_splat(P[i])));
    }
    v128_or(zero, is_p)
}

fn select_base(a: &[v128; 9], b: &[v128; 9], mask: v128) -> [v128; 9] {
    core::array::from_fn(|i| v128_bitselect(a[i], b[i], mask))
}

impl Lanes4 for U29x9 {
    type V = U29x9x4;
    #[inline(always)]
    fn pack(e: &[Self; 4]) -> U29x9x4 {
        U29x9x4::pack([&e[0], &e[1], &e[2], &e[3]])
    }
    #[inline(always)]
    fn unpack(v: &U29x9x4) -> [Self; 4] {
        v.unpack()
    }
    #[inline(always)]
    fn mul4(a: &U29x9x4, b: &U29x9x4) -> U29x9x4 {
        U29x9x4(mul4_call(&a.0, &b.0))
    }
    #[inline(always)]
    fn sqr4(a: &U29x9x4) -> U29x9x4 {
        U29x9x4(sqr4_call(&a.0))
    }
    #[inline(always)]
    fn add4(a: &U29x9x4, b: &U29x9x4) -> U29x9x4 {
        U29x9x4(simd::add4(&a.0, &b.0))
    }
    #[inline(always)]
    fn sub4(a: &U29x9x4, b: &U29x9x4) -> U29x9x4 {
        U29x9x4(simd::sub4(&a.0, &b.0))
    }
    fn zero_lanes(v: &U29x9x4) -> v128 {
        zero_lanes_base(&v.0)
    }
    fn select(a: &U29x9x4, b: &U29x9x4, mask: v128) -> U29x9x4 {
        U29x9x4(select_base(&a.0, &b.0, mask))
    }
}

#[derive(Clone, Copy)]
pub struct Fq2x4 {
    pub c0: U29x9x4,
    pub c1: U29x9x4,
}

impl Lanes4 for Fq2Simd {
    type V = Fq2x4;
    #[inline(always)]
    fn pack(e: &[Self; 4]) -> Fq2x4 {
        Fq2x4 {
            c0: U29x9x4::pack([&e[0].0, &e[1].0, &e[2].0, &e[3].0]),
            c1: U29x9x4::pack([&e[0].1, &e[1].1, &e[2].1, &e[3].1]),
        }
    }
    #[inline(always)]
    fn unpack(v: &Fq2x4) -> [Self; 4] {
        let (c0, c1) = (v.c0.unpack(), v.c1.unpack());
        core::array::from_fn(|l| Fq2Simd(c0[l], c1[l]))
    }
    /// Karatsuba: three 4-lane base multiplications for four Fq2 products.
    #[inline(always)]
    fn mul4(a: &Fq2x4, b: &Fq2x4) -> Fq2x4 {
        let v0 = mul4_call(&a.c0.0, &b.c0.0);
        let v1 = mul4_call(&a.c1.0, &b.c1.0);
        let sa = simd::add4(&a.c0.0, &a.c1.0);
        let sb = simd::add4(&b.c0.0, &b.c1.0);
        let v2 = mul4_call(&sa, &sb);
        Fq2x4 {
            c0: U29x9x4(simd::sub4(&v0, &v1)),
            c1: U29x9x4(simd::sub4(&simd::sub4(&v2, &v0), &v1)),
        }
    }
    /// Complex squaring: (a0 + a1)(a0 - a1), 2 a0 a1.
    #[inline(always)]
    fn sqr4(a: &Fq2x4) -> Fq2x4 {
        let s = simd::add4(&a.c0.0, &a.c1.0);
        let d = simd::sub4(&a.c0.0, &a.c1.0);
        let t = simd::add4(&a.c0.0, &a.c0.0);
        Fq2x4 {
            c0: U29x9x4(mul4_call(&s, &d)),
            c1: U29x9x4(mul4_call(&t, &a.c1.0)),
        }
    }
    #[inline(always)]
    fn add4(a: &Fq2x4, b: &Fq2x4) -> Fq2x4 {
        Fq2x4 {
            c0: U29x9x4(simd::add4(&a.c0.0, &b.c0.0)),
            c1: U29x9x4(simd::add4(&a.c1.0, &b.c1.0)),
        }
    }
    #[inline(always)]
    fn sub4(a: &Fq2x4, b: &Fq2x4) -> Fq2x4 {
        Fq2x4 {
            c0: U29x9x4(simd::sub4(&a.c0.0, &b.c0.0)),
            c1: U29x9x4(simd::sub4(&a.c1.0, &b.c1.0)),
        }
    }
    fn zero_lanes(v: &Fq2x4) -> v128 {
        v128_and(zero_lanes_base(&v.c0.0), zero_lanes_base(&v.c1.0))
    }
    fn select(a: &Fq2x4, b: &Fq2x4, mask: v128) -> Fq2x4 {
        Fq2x4 {
            c0: U29x9x4(select_base(&a.c0.0, &b.c0.0, mask)),
            c1: U29x9x4(select_base(&a.c1.0, &b.c1.0, mask)),
        }
    }
}
