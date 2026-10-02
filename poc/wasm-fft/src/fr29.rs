//! BN254 scalar field Fr in nine 29-bit limbs (same algorithm and bounds as
//! poc/wasm-field's u29x9 for Fq; r < 2^254 as well, so every bound carries
//! over). Constants derived with Python from
//! r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001.
//!
//! Data trick: an arkworks Fr stores x * 2^256 mod r. Reinterpreting that
//! integer in 29-bit limbs and multiplying it by a constant held in *this*
//! representation (c * 2^261) with the 2^-261 Montgomery multiply gives
//! (x * c) * 2^256 mod r, i.e. again arkworks' Montgomery form. So FFT data
//! never needs a conversion multiply: only the limb repacking, plus a final
//! conditional subtraction (values are kept below 2r).

use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};

pub use crate::gen_u29::mont_mul;

pub const W: u32 = 29;
pub const MASK: u32 = (1 << W) - 1;
const MASK64: u64 = MASK as u64;

pub const P: [u32; 9] = [
    0x10000001, 0x1f0fac9f, 0x0e5c2450, 0x07d090f3, 0x1585d283, 0x02db40c0, 0x00a6e141, 0x0e5c2634,
    0x0030644e,
];
pub const P2: [u32; 9] = [
    0x00000002, 0x1e1f593f, 0x1cb848a1, 0x0fa121e6, 0x0b0ba506, 0x05b68181, 0x014dc282, 0x1cb84c68,
    0x0060c89c,
];
/// -r^-1 mod 2^29.
pub const MU: u32 = 0x0fffffff;
/// 2^266 mod r: mont_mul(x * 2^256, TO) = x * 2^261.
pub const TO: [u32; 9] = [
    0x0fffead7, 0x1d5444f4, 0x04438aa5, 0x03b4d096, 0x134c84da, 0x0e92d304, 0x14cb95b3, 0x041b9d3d,
    0x00058003,
];

#[inline(always)]
pub fn sub_if_geq(a: [u32; 9], m: &[u32; 9]) -> [u32; 9] {
    let mut d = [0u32; 9];
    let mut borrow = 0i32;
    for i in 0..9 {
        let v = a[i] as i32 - m[i] as i32 + borrow;
        d[i] = (v as u32) & MASK;
        borrow = v >> W;
    }
    let keep = borrow as u32;
    let mut r = [0u32; 9];
    for i in 0..9 {
        r[i] = (a[i] & keep) | (d[i] & !keep);
    }
    r
}

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

/// arkworks Fr -> raw limbs of its Montgomery integer (x * 2^256).
#[inline(always)]
pub fn raw_from_ark(x: &Fr) -> [u32; 9] {
    from_u64x4(&(x.0).0)
}

/// Raw limbs (value < 2r) -> arkworks Fr.
#[inline(always)]
pub fn raw_to_ark(a: &[u32; 9]) -> Fr {
    Fr::new_unchecked(BigInt::new(to_u64x4(&sub_if_geq(*a, &P))))
}

/// arkworks Fr -> this crate's Montgomery form (x * 2^261), for constants.
#[inline(always)]
pub fn const_from_ark(x: &Fr) -> [u32; 9] {
    mont_mul(&raw_from_ark(x), &TO)
}

#[inline(always)]
pub fn add(a: &[u32; 9], b: &[u32; 9]) -> [u32; 9] {
    let mut s = [0u32; 9];
    let mut carry = 0u32;
    for i in 0..9 {
        let v = a[i] + b[i] + carry;
        s[i] = v & MASK;
        carry = v >> W;
    }
    sub_if_geq(s, &P2)
}

#[inline(always)]
pub fn sub(a: &[u32; 9], b: &[u32; 9]) -> [u32; 9] {
    let mut d = [0u32; 9];
    let mut borrow = 0i32;
    for i in 0..9 {
        let v = a[i] as i32 - b[i] as i32 + borrow;
        d[i] = (v as u32) & MASK;
        borrow = v >> W;
    }
    let mask = borrow as u32;
    let mut carry = 0u32;
    for i in 0..9 {
        let v = d[i] + (P2[i] & mask) + carry;
        d[i] = v & MASK;
        carry = v >> W;
    }
    d
}

/// Differential tests of the scalar Fr arithmetic against arkworks (works
/// natively and in WASM). Returns the number of checks.
pub fn check_scalar(seed: u64, random: usize) -> u64 {
    use ark_ff::{Field, UniformRand};
    use ark_std::rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(seed);
    let mut n = 0u64;
    let r_minus = |k: u64| -> Fr { -Fr::from(k) };
    let mut edges: Vec<Fr> = vec![Fr::from(0u64), Fr::from(1u64), Fr::from(2u64), r_minus(1), r_minus(2)];
    edges.push(Fr::from(2u64).inverse().unwrap());
    edges.push(-Fr::from(2u64).inverse().unwrap());
    for k in [28u32, 29, 30, 32, 58, 63, 64, 87, 116, 128, 145, 174, 192, 203, 232, 253] {
        let p = Fr::from(2u64).pow([k as u64]);
        edges.extend([p, p - Fr::from(1u64), p + Fr::from(1u64)]);
    }
    for _ in 0..8 {
        edges.push(Fr::rand(&mut rng));
    }
    let mut pairs: Vec<(Fr, Fr)> = Vec::new();
    for a in &edges {
        for b in &edges {
            pairs.push((*a, *b));
        }
    }
    for _ in 0..random {
        pairs.push((Fr::rand(&mut rng), Fr::rand(&mut rng)));
    }
    for (a, b) in &pairs {
        let (ra, rb) = (raw_from_ark(a), raw_from_ark(b));
        let cb = const_from_ark(b);
        assert_eq!(raw_to_ark(&mont_mul(&ra, &cb)), *a * b, "mul");
        assert_eq!(raw_to_ark(&add(&ra, &rb)), *a + b, "add");
        assert_eq!(raw_to_ark(&sub(&ra, &rb)), *a - b, "sub");
        assert_eq!(raw_to_ark(&ra), *a, "roundtrip");
        // Both encodings x and x + r into mul (weakly reduced inputs).
        let rap = {
            let mut s = [0u32; 9];
            let mut c = 0;
            for i in 0..9 {
                let v = ra[i] + P[i] + c;
                s[i] = v & MASK;
                c = v >> W;
            }
            s
        };
        let res = mont_mul(&rap, &cb);
        let c1 = sub_if_geq(res, &P);
        assert_eq!(sub_if_geq(c1, &P), c1, "bound < 2r");
        assert_eq!(raw_to_ark(&res), *a * b, "mul x+r");
        n += 5;
    }
    // Chains: 1M-ish mixed ops staying in raw form.
    let (mut x, mut ax) = (raw_from_ark(&edges[10]), edges[10]);
    for i in 0..(random * 4) {
        let b = pairs[i % pairs.len()].1;
        match i % 3 {
            0 => {
                x = mont_mul(&x, &const_from_ark(&b));
                ax *= b;
            }
            1 => {
                x = add(&x, &raw_from_ark(&b));
                ax += b;
            }
            _ => {
                x = sub(&x, &raw_from_ark(&b));
                ax -= b;
            }
        }
        n += 1;
    }
    assert_eq!(raw_to_ark(&x), ax, "chain");
    let _ = Fr::MODULUS;
    n
}
