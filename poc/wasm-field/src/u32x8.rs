//! Representation 2: eight saturated 32-bit limbs, CIOS Montgomery
//! multiplication with 64-bit accumulators (a native `i64.mul` in WASM).
//!
//! R = 2^256, the same Montgomery radix as arkworks, so converting to and from
//! `ark_bn254::Fq` only reinterprets the limbs (little-endian 4x64 <-> 8x32).
//! Values are always fully reduced (`< p`), so equality is limb equality.
//!
//! Multiplication is gnark's "no-carry" CIOS: valid because the top 32-bit
//! word of p (0x30644e72) is below (2^32 - 1) / 2 - 1. Every step computes
//! `t + a * b + carry <= (2^32 - 1) + (2^32 - 1)^2 + (2^32 - 1) = 2^64 - 1`,
//! so a u64 never overflows. Squaring reuses multiplication.

use ark_bn254::Fq;

use crate::field::{PocField, ark_from_mont_limbs, ark_mont_limbs};

/// p in 32-bit little-endian limbs.
pub const P: [u32; 8] = [
    0xd87cfd47, 0x3c208c16, 0x6871ca8d, 0x97816a91, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
];
/// -p^-1 mod 2^32.
pub const MU: u32 = 0xe4866389;
/// R mod p, the Montgomery form of 1.
const ONE: [u32; 8] = [
    0xc58f0d9d, 0xd35d438d, 0xf5c70b3d, 0x0a78eb28, 0x7879462c, 0x666ea36f, 0x9a07df2f, 0x0e0a77c1,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct U32x8(pub [u32; 8]);

/// `a - p` if `a >= p`, else `a` (branchless). `a` must be `< 2p`.
#[inline(always)]
fn reduce_once(a: [u32; 8]) -> [u32; 8] {
    let mut d = [0u32; 8];
    let mut borrow = 0u64;
    for i in 0..8 {
        let v = (a[i] as u64).wrapping_sub(P[i] as u64).wrapping_sub(borrow);
        d[i] = v as u32;
        borrow = (v >> 63) & 1;
    }
    // borrow = 1 means a < p: keep a.
    let keep = 0u32.wrapping_sub(borrow as u32);
    let mut r = [0u32; 8];
    for i in 0..8 {
        r[i] = (a[i] & keep) | (d[i] & !keep);
    }
    r
}

#[inline(always)]
pub fn mont_mul(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut t = [0u32; 8];
    for i in 0..8 {
        let bi = b[i] as u64;
        let v = t[0] as u64 + a[0] as u64 * bi;
        let mut carry_a = v >> 32;
        let t0 = v as u32;
        let m = t0.wrapping_mul(MU) as u64;
        let mut carry_m = (t0 as u64 + m * P[0] as u64) >> 32;
        for j in 1..8 {
            let v = t[j] as u64 + a[j] as u64 * bi + carry_a;
            carry_a = v >> 32;
            let w = (v as u32) as u64 + m * P[j] as u64 + carry_m;
            carry_m = w >> 32;
            t[j - 1] = w as u32;
        }
        t[7] = (carry_a + carry_m) as u32;
    }
    reduce_once(t)
}

impl PocField for U32x8 {
    type Ark = Fq;
    const NAME: &'static str = "u32x8";
    #[inline(always)]
    fn zero() -> Self {
        U32x8([0; 8])
    }
    #[inline(always)]
    fn one() -> Self {
        U32x8(ONE)
    }
    #[inline(always)]
    fn from_ark(x: &Fq) -> Self {
        let l = ark_mont_limbs(x);
        let mut r = [0u32; 8];
        for i in 0..4 {
            r[2 * i] = l[i] as u32;
            r[2 * i + 1] = (l[i] >> 32) as u32;
        }
        U32x8(r)
    }
    #[inline(always)]
    fn to_ark(&self) -> Fq {
        let mut l = [0u64; 4];
        for (i, limb) in l.iter_mut().enumerate() {
            *limb = self.0[2 * i] as u64 | ((self.0[2 * i + 1] as u64) << 32);
        }
        ark_from_mont_limbs(l)
    }
    #[inline(always)]
    fn add(&self, rhs: &Self) -> Self {
        // a + b < 2p < 2^255: no carry out of the top limb.
        let mut s = [0u32; 8];
        let mut carry = 0u64;
        for i in 0..8 {
            let v = self.0[i] as u64 + rhs.0[i] as u64 + carry;
            s[i] = v as u32;
            carry = v >> 32;
        }
        U32x8(reduce_once(s))
    }
    #[inline(always)]
    fn sub(&self, rhs: &Self) -> Self {
        let mut d = [0u32; 8];
        let mut borrow = 0u64;
        for i in 0..8 {
            let v = (self.0[i] as u64)
                .wrapping_sub(rhs.0[i] as u64)
                .wrapping_sub(borrow);
            d[i] = v as u32;
            borrow = (v >> 63) & 1;
        }
        // On borrow add p back (mod 2^256).
        let mask = 0u32.wrapping_sub(borrow as u32);
        let mut carry = 0u64;
        for i in 0..8 {
            let v = d[i] as u64 + (P[i] & mask) as u64 + carry;
            d[i] = v as u32;
            carry = v >> 32;
        }
        U32x8(d)
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
        U32x8(mont_mul(&self.0, &rhs.0))
    }
    #[inline(always)]
    fn square(&self) -> Self {
        U32x8(mont_mul(&self.0, &self.0))
    }
    #[inline(always)]
    fn is_zero(&self) -> bool {
        self.0 == [0; 8]
    }
    #[inline(always)]
    fn equals(&self, rhs: &Self) -> bool {
        self.0 == rhs.0
    }
}
