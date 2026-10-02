//! Radix-2 NTT over BN254 Fr with the 4-lane simd128 9x29 multiply.
//!
//! Layout: n elements as q = n/4 limb-sliced vectors, vector k holding
//! elements k, k+q, k+2q, k+3q ("strided lanes"). Decimation in frequency
//! (natural in, bit-reversed out):
//! - stages with half-size n/2 and n/4 pair lanes inside one vector; they
//!   run fused as one radix-4 pass with lane shuffles (one mul4 each, half
//!   the lanes useful);
//! - every later stage pairs whole vectors k, k+m with ONE twiddle shared by
//!   all four lanes (a splat), so four butterflies per vector op;
//! - the bit reversal is folded into the unpack: vector k lands at the four
//!   contiguous outputs 4*rev(k) .. 4*rev(k)+3 (lane order 0, 2, 1, 3).
//!
//! Data stays in arkworks' Montgomery integer (see fr29.rs), so packing is
//! limb repacking only; twiddles and scale factors are in the 2^261 form.

use ark_bn254::Fr;
use ark_ff::{Field, One};
use core::arch::wasm32::*;

use super::fr29::{MASK, P2, W, const_from_ark, mont_mul, raw_from_ark, raw_to_ark};
use super::gen_u29::mul4;

pub type V = [v128; 9];

#[inline(always)]
fn splat(c: &[u32; 9]) -> V {
    let mut v = [u32x4_splat(0); 9];
    for i in 0..9 {
        v[i] = u32x4_splat(c[i]);
    }
    v
}

#[inline(always)]
fn lanes2(a: &[u32; 9], b: &[u32; 9]) -> V {
    let mut v = [u32x4_splat(0); 9];
    for i in 0..9 {
        v[i] = u32x4(a[i], b[i], a[i], b[i]);
    }
    v
}

#[inline(always)]
fn add4(a: &V, b: &V) -> V {
    let mask = u32x4_splat(MASK);
    let mut s = [u32x4_splat(0); 9];
    let mut carry = u32x4_splat(0);
    for i in 0..9 {
        let v = u32x4_add(u32x4_add(a[i], b[i]), carry);
        s[i] = v128_and(v, mask);
        carry = u32x4_shr(v, W);
    }
    let mut d = [u32x4_splat(0); 9];
    let mut borrow = i32x4_splat(0);
    for i in 0..9 {
        let v = i32x4_add(i32x4_sub(s[i], u32x4_splat(P2[i])), borrow);
        d[i] = v128_and(v, mask);
        borrow = i32x4_shr(v, W);
    }
    for i in 0..9 {
        d[i] = v128_bitselect(s[i], d[i], borrow);
    }
    d
}

#[inline(always)]
fn sub4(a: &V, b: &V) -> V {
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

/// Twiddles for one domain size and direction: omega^k, k < n/2, 2^261 form.
pub struct Plan {
    pub n: usize,
    pub tw: Vec<[u32; 9]>,
}

impl Plan {
    pub fn new(n: usize, omega: Fr) -> Self {
        assert!(n.is_power_of_two() && n >= 8);
        let w = const_from_ark(&omega);
        let mut tw = Vec::with_capacity(n / 2);
        let mut cur = const_from_ark(&Fr::one());
        for _ in 0..n / 2 {
            tw.push(cur);
            cur = mont_mul(&cur, &w);
        }
        Plan { n, tw }
    }
}

#[inline(always)]
fn rev(k: usize, bits: u32) -> usize {
    if bits == 0 {
        0
    } else {
        k.reverse_bits() >> (usize::BITS - bits)
    }
}

/// Pack (optionally scaling element i by c * g^i), returns the vectors.
pub fn pack(x: &[Fr], buf: &mut Vec<V>, pre: Option<(Fr, Fr)>) {
    let n = x.len();
    let q = n / 4;
    buf.clear();
    buf.reserve(q);
    let mut m = [u32x4_splat(0); 9];
    let mut step = m;
    if let Some((g, c)) = pre {
        let gq = g.pow([q as u64]);
        let e: Vec<[u32; 9]> = (0..4u64)
            .map(|l| const_from_ark(&(c * gq.pow([l]))))
            .collect();
        for i in 0..9 {
            m[i] = u32x4(e[0][i], e[1][i], e[2][i], e[3][i]);
        }
        step = splat(&const_from_ark(&g));
    }
    for k in 0..q {
        let e = [
            raw_from_ark(&x[k]),
            raw_from_ark(&x[k + q]),
            raw_from_ark(&x[k + 2 * q]),
            raw_from_ark(&x[k + 3 * q]),
        ];
        let mut v = [u32x4_splat(0); 9];
        for i in 0..9 {
            v[i] = u32x4(e[0][i], e[1][i], e[2][i], e[3][i]);
        }
        if pre.is_some() {
            v = mul4(&v, &m);
            m = mul4(&m, &step);
        }
        buf.push(v);
    }
}

/// Unpack with the bit reversal (optionally scaling every element by c).
pub fn unpack(buf: &[V], x: &mut [Fr], post: Option<Fr>) {
    let q = buf.len();
    let bits = q.trailing_zeros();
    let c = post.map(|c| splat(&const_from_ark(&c)));
    for k in 0..q {
        let mut v = buf[k];
        if let Some(c) = &c {
            v = mul4(&v, c);
        }
        let base = 4 * rev(k, bits);
        let mut e = [[0u32; 9]; 4];
        for i in 0..9 {
            e[0][i] = u32x4_extract_lane::<0>(v[i]);
            e[1][i] = u32x4_extract_lane::<1>(v[i]);
            e[2][i] = u32x4_extract_lane::<2>(v[i]);
            e[3][i] = u32x4_extract_lane::<3>(v[i]);
        }
        x[base] = raw_to_ark(&e[0]);
        x[base + 1] = raw_to_ark(&e[2]);
        x[base + 2] = raw_to_ark(&e[1]);
        x[base + 3] = raw_to_ark(&e[3]);
    }
}

/// The DIF butterflies on packed data.
pub fn dif(plan: &Plan, buf: &mut [V]) {
    let n = plan.n;
    let q = n / 4;
    assert_eq!(buf.len(), q);
    let tw = &plan.tw;
    // Fused cross-lane stages (half-size n/2, then n/4).
    for k in 0..q {
        let v = buf[k];
        let mut lo = [u32x4_splat(0); 9];
        let mut hi = lo;
        for i in 0..9 {
            lo[i] = i32x4_shuffle::<0, 1, 0, 1>(v[i], v[i]);
            hi[i] = i32x4_shuffle::<2, 3, 2, 3>(v[i], v[i]);
        }
        let s = add4(&lo, &hi);
        let d = mul4(&sub4(&lo, &hi), &lanes2(&tw[k], &tw[k + q]));
        let mut v = [u32x4_splat(0); 9];
        for i in 0..9 {
            v[i] = i32x4_shuffle::<0, 1, 6, 7>(s[i], d[i]);
        }
        for i in 0..9 {
            lo[i] = i32x4_shuffle::<0, 0, 2, 2>(v[i], v[i]);
            hi[i] = i32x4_shuffle::<1, 1, 3, 3>(v[i], v[i]);
        }
        let s = add4(&lo, &hi);
        let d = mul4(&sub4(&lo, &hi), &splat(&tw[2 * k]));
        for i in 0..9 {
            v[i] = i32x4_shuffle::<0, 5, 2, 7>(s[i], d[i]);
        }
        buf[k] = v;
    }
    // Vector stages: pairs (k, k+m), one splatted twiddle omega^(j * n/2m).
    let mut m = q / 2;
    while m >= 1 {
        let stride = n / (2 * m);
        for blk in (0..q).step_by(2 * m) {
            let (a, b) = buf[blk..blk + 2 * m].split_at_mut(m);
            // j = 0: twiddle 1, no multiply.
            let (x, y) = (a[0], b[0]);
            a[0] = add4(&x, &y);
            b[0] = sub4(&x, &y);
            for j in 1..m {
                let (x, y) = (a[j], b[j]);
                a[j] = add4(&x, &y);
                b[j] = mul4(&sub4(&x, &y), &splat(&tw[j * stride]));
            }
        }
        m /= 2;
    }
}

/// Forward NTT with root omega (natural order in and out).
pub fn ntt(plan: &Plan, x: &mut [Fr], buf: &mut Vec<V>, pre: Option<(Fr, Fr)>, post: Option<Fr>) {
    assert_eq!(x.len(), plan.n);
    pack(x, buf, pre);
    dif(plan, buf);
    unpack(buf, x, post);
}
