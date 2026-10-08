//! Representation 3: nine unsaturated 29-bit limbs with lazy carries, in the
//! style of Gregor Mitschabaude's ZPrize WASM MSM (github.com/mitschabaude/montgomery).
//!
//! # Choosing the limb width (p < 2^254)
//!
//! Interleaved (operand-scanning) Montgomery multiplication adds, per outer
//! iteration, one `a_i * b_j` and one `q_i * p_j` product to each of the n
//! column accumulators, then shifts the columns down by one limb and carries
//! only the lowest column. A column therefore collects at most `2n` products
//! (`n` from `a * b`, `n` from `q * p`) plus one incoming carry of at most
//! `2^(64 - w)` before it is retired. With limbs below `2^w` every product is
//! below `2^(2w)`, so u64 columns never overflow if
//! `2n * 2^(2w) + 2^(64 - w) <= 2^64`. The radix `R = 2^(nw)` must exceed 4p
//! for the `[0, 2p)` invariant below, so `nw >= 256`:
//!
//! | w | n = ceil(256 / w) | 2n * 2^(2w) | products (2n^2) | fits u64 |
//! |---|---|---|---|---|
//! | 32 | 8 | 2^68 | 128 | no: needs per-product carries (representation 2) |
//! | 30 | 9 | 2^64.17 | 162 | no: needs a mid-loop carry |
//! | **29** | **9** | **2^62.17** | **162** | **yes, with 1.8 bits to spare** |
//! | 28 | 10 | 2^60.32 | 200 | yes, but 23% more products |
//! | 26 | 10 | 2^56.32 | 200 | yes, but 23% more products |
//!
//! 9x29 is the fewest products with no carries inside the loop.
//!
//! # Invariants and lazy reduction
//!
//! R = 2^261. Stored values are *weakly reduced*: value `< 2p`, limbs `< 2^29`.
//! `mont_mul`/`mont_sqr` return `(a*b + Q*p) / R < a*b/R + p`, which is `< 2p`
//! whenever `a*b < p*R`; that holds for any inputs below 2^257 (about 11.7p),
//! so sums of a few weakly reduced values may be multiplied unreduced.
//! Inputs may also carry unnormalized limbs up to `2^30 - 1` (for example a
//! limb-wise sum of two normalized values, without carry propagation) as long
//! as the value stays below 2^257: then a
//! column is at most `9 * 2^60 + 9 * 2^58 + 2^35 < 2^63.5` for multiplication,
//! and for squaring at most `2 * 4 * 2^60 + 2^60 + 9 * 2^58 + 2^35 < 2^63.5`.
//! The differential tests exercise both relaxations.
//!
//! Squaring computes each cross product once and doubles the column (45
//! products instead of 81), then reduces separately (81 more).

use ark_bn254::Fq;

use crate::msm_simd::field::{PocField, ark_from_mont_limbs, ark_mont_limbs};
pub use crate::msm_simd::gen_u29::{mont_mul, mont_sqr};

pub const W: u32 = 29;
pub const MASK: u32 = (1 << W) - 1;
const MASK64: u64 = MASK as u64;

/// p in 29-bit limbs.
pub const P: [u32; 9] = [
    0x187cfd47, 0x010460b6, 0x1c72a34f, 0x02d522d0, 0x1585d978, 0x02db40c0, 0x00a6e141, 0x0e5c2634,
    0x0030644e,
];
/// 2p in 29-bit limbs.
pub const P2: [u32; 9] = [
    0x10f9fa8e, 0x0208c16d, 0x18e5469e, 0x05aa45a1, 0x0b0bb2f0, 0x05b68181, 0x014dc282, 0x1cb84c68,
    0x0060c89c,
];
/// -p^-1 mod 2^29.
pub const MU: u32 = 0x04866389;
/// R mod p = 2^261 mod p, the Montgomery form of 1.
const ONE: [u32; 9] = [
    0x157ccc21, 0x141c2758, 0x185230d3, 0x014c0419, 0x0aa36fb9, 0x1d4240ce, 0x11d54c07, 0x052ac7a8,
    0x000dc836,
];
/// 2^266 mod p: `mont_mul(a * 2^256, TO) = a * 2^261` converts arkworks'
/// Montgomery form to this one.
const TO: [u32; 9] = [
    0x13349ca1, 0x1a5d84a8, 0x0a3e5cac, 0x100249e0, 0x12b951e8, 0x0e92d304, 0x14cb95b3, 0x041b9d3d,
    0x00058003,
];
/// 2^256 mod p: `mont_mul(a * 2^261, FROM) = a * 2^256` converts back.
const FROM: [u32; 9] = [
    0x058f0d9d, 0x1aea1c6e, 0x11c2cf74, 0x11d651eb, 0x1462c0a7, 0x11b7bc3c, 0x1cbd99ba, 0x183340fb,
    0x000e0a77,
];

#[derive(Clone, Copy, Debug, Default)]
#[repr(transparent)]
pub struct U29x9(pub [u32; 9]);

/// `a - m` if `a >= m`, else `a` (branchless); limbs normalized.
#[inline(always)]
fn sub_if_geq(a: [u32; 9], m: &[u32; 9]) -> [u32; 9] {
    let mut d = [0u32; 9];
    let mut borrow = 0i32;
    for i in 0..9 {
        let v = a[i] as i32 - m[i] as i32 + borrow;
        d[i] = (v as u32) & MASK;
        borrow = v >> W;
    }
    // borrow is -1 when a < m: keep a.
    let keep = borrow as u32;
    let mut r = [0u32; 9];
    for i in 0..9 {
        r[i] = (a[i] & keep) | (d[i] & !keep);
    }
    r
}

/// The canonical (`< p`) limbs of a weakly reduced value.
#[inline(always)]
pub fn canonical(a: &[u32; 9]) -> [u32; 9] {
    sub_if_geq(*a, &P)
}

/// 4x64 little-endian integer to 29-bit limbs (the value must be < 2^261).
#[inline(always)]
pub fn from_u64x4(l: &[u64; 4]) -> [u32; 9] {
    let mut r = [0u32; 9];
    for (i, limb) in r.iter_mut().enumerate() {
        let bit = 29 * i;
        let (word, shift) = (bit / 64, bit % 64);
        let mut v = l[word] >> shift;
        if shift > 35 && word + 1 < 4 {
            v |= l[word + 1] << (64 - shift);
        }
        *limb = (v & MASK64) as u32;
    }
    r
}

/// Normalized 29-bit limbs to a 4x64 integer (the value must be < 2^256).
#[inline(always)]
pub fn to_u64x4(a: &[u32; 9]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, &limb) in a.iter().enumerate() {
        let bit = 29 * i;
        let (word, shift) = (bit / 64, bit % 64);
        out[word] |= (limb as u64) << shift;
        if shift > 35 && word + 1 < 4 {
            out[word + 1] |= (limb as u64) >> (64 - shift);
        }
    }
    out
}

impl PocField for U29x9 {
    type Ark = Fq;
    #[inline(always)]
    fn zero() -> Self {
        U29x9([0; 9])
    }
    #[inline(always)]
    fn one() -> Self {
        U29x9(ONE)
    }
    #[inline(always)]
    fn from_ark(x: &Fq) -> Self {
        U29x9(mont_mul(&from_u64x4(&ark_mont_limbs(x)), &TO))
    }
    #[inline(always)]
    fn to_ark(&self) -> Fq {
        let mont = canonical(&mont_mul(&self.0, &FROM));
        ark_from_mont_limbs(to_u64x4(&mont))
    }
    #[inline(always)]
    fn add(&self, rhs: &Self) -> Self {
        // < 4p, limbs below 2^30 + 1 before the carry pass: u32 is enough.
        let mut s = [0u32; 9];
        let mut carry = 0u32;
        for i in 0..9 {
            let v = self.0[i] + rhs.0[i] + carry;
            s[i] = v & MASK;
            carry = v >> W;
        }
        U29x9(sub_if_geq(s, &P2))
    }
    #[inline(always)]
    fn sub(&self, rhs: &Self) -> Self {
        let mut d = [0u32; 9];
        let mut borrow = 0i32;
        for i in 0..9 {
            let v = self.0[i] as i32 - rhs.0[i] as i32 + borrow;
            d[i] = (v as u32) & MASK;
            borrow = v >> W;
        }
        // On borrow, add 2p modulo 2^261 (the top carry is dropped by the mask).
        let mask = borrow as u32;
        let mut carry = 0u32;
        for i in 0..9 {
            let v = d[i] + (P2[i] & mask) + carry;
            d[i] = v & MASK;
            carry = v >> W;
        }
        U29x9(d)
    }
    #[inline(always)]
    fn double(&self) -> Self {
        self.add(self)
    }
    #[inline(always)]
    fn neg(&self) -> Self {
        Self::zero().sub(self)
    }
    #[inline(always)]
    fn mul(&self, rhs: &Self) -> Self {
        U29x9(mont_mul(&self.0, &rhs.0))
    }
    #[inline(always)]
    fn square(&self) -> Self {
        U29x9(mont_sqr(&self.0))
    }
    #[inline(always)]
    fn is_zero(&self) -> bool {
        canonical(&self.0) == [0; 9]
    }
    #[inline(always)]
    fn equals(&self, rhs: &Self) -> bool {
        canonical(&self.0) == canonical(&rhs.0)
    }
}
