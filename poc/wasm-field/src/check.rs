//! Differential tests against arkworks. They are ordinary functions (not
//! `#[test]`s) so the same code runs natively and inside the WASM module, where
//! a WASM-only miscompilation would show up. Any mismatch panics with the
//! failing operation and operands.

use ark_bn254::{Fq, Fq2, Fr};
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, BigInt, BigInteger, Field, PrimeField, UniformRand, Zero};
use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};

use crate::field::{Ark, PocField};
use crate::fq2::{Fq2Ark, Fq2Of};
use crate::msm::{self, Phases, Stats};
use crate::u29x9::{self, U29x9};
use crate::u32x8::{self, U32x8};

#[derive(Default)]
pub struct Tally {
    pub checks: u64,
    pub sections: Vec<(String, u64)>,
}

impl Tally {
    fn section(&mut self, name: &str, checks: u64) {
        self.checks += checks;
        self.sections.push((name.to_string(), checks));
    }

    pub fn json(&self) -> String {
        let sections = self
            .sections
            .iter()
            .map(|(name, n)| format!("{{\"name\":\"{name}\",\"checks\":{n}}}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"ok\":true,\"checks\":{},\"sections\":[{sections}]}}",
            self.checks
        )
    }
}

/// Little-endian bytes of `sum_i limbs[i] * 2^(w*i)` (limbs may exceed 2^w).
pub fn limbs_to_bytes(limbs: &[u32], w: usize) -> Vec<u8> {
    let mut acc = [0u64; 6];
    for (i, &v) in limbs.iter().enumerate() {
        let bit = w * i;
        let (mut word, shift) = (bit / 64, bit % 64);
        let mut add = (v as u128) << shift;
        let mut carry = 0u128;
        while add != 0 || carry != 0 {
            let s = acc[word] as u128 + (add & u64::MAX as u128) + carry;
            acc[word] = s as u64;
            carry = s >> 64;
            add >>= 64;
            word += 1;
        }
    }
    acc.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Field element represented by raw Montgomery limbs with radix `2^(w*n)`.
pub fn raw_to_ark(limbs: &[u32], w: usize) -> Fq {
    let x = Fq::from_le_bytes_mod_order(&limbs_to_bytes(limbs, w));
    let r = Fq::from(2u64).pow([(w * limbs.len()) as u64]);
    x * r.inverse().unwrap()
}

/// 29-bit limbs of a (possibly >= p) integer given as little-endian u64 words.
fn int_to_29(words: &[u64]) -> [u32; 9] {
    let mut l = [0u64; 4];
    l[..words.len()].copy_from_slice(words);
    u29x9::from_u64x4(&l)
}

fn int_from_bigint(x: &BigInt<4>) -> [u64; 4] {
    x.0
}

fn biguint_add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = a[i] as u128 + b[i] as u128 + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    out
}

fn biguint_sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let s = a[i] as i128 - b[i] as i128 + borrow;
        out[i] = s as u64;
        borrow = if s < 0 { -1 } else { 0 };
    }
    out
}

fn pow2(k: usize) -> [u64; 4] {
    let mut out = [0u64; 4];
    if k < 256 {
        out[k / 64] = 1 << (k % 64);
    }
    out
}

/// Integers near the boundaries every representation cares about.
fn boundary_integers() -> Vec<[u64; 4]> {
    let p = int_from_bigint(&Fq::MODULUS);
    let one = pow2(0);
    let two = pow2(1);
    let mut v = vec![
        [0; 4],
        one,
        two,
        biguint_sub(p, one),
        biguint_sub(p, two),
        // (p - 1) / 2 and (p + 1) / 2
        {
            let mut h = biguint_sub(p, one);
            for i in 0..4 {
                h[i] = (h[i] >> 1) | if i < 3 { h[i + 1] << 63 } else { 0 };
            }
            h
        },
    ];
    let half = v[5];
    v.push(biguint_add(half, one));
    let mut ks: Vec<usize> = (1..9).map(|i| 29 * i).collect();
    ks.extend((1..8).map(|i| 32 * i));
    ks.extend([64, 128, 192, 253]);
    for k in ks {
        let b = pow2(k);
        v.push(biguint_sub(b, one));
        v.push(b);
        v.push(biguint_add(b, one));
    }
    // Every 29-bit / 32-bit limb at its maximum, below p.
    v.push(int_from_bigint(&BigInt([
        u64::MAX,
        u64::MAX,
        u64::MAX,
        0x0fff_ffff_ffff_ffff,
    ])));
    v.retain(|x| BigInt(*x) < Fq::MODULUS);
    v
}

/// Edge field elements, both as canonical integers and as raw arkworks
/// Montgomery forms (which is also the u32x8 representation).
pub fn edge_elements() -> Vec<Fq> {
    let mut out = Vec::new();
    for x in boundary_integers() {
        out.push(Fq::from_bigint(BigInt(x)).unwrap());
        out.push(Fq::new_unchecked(BigInt(x)));
    }
    out.push(Fq::ONE);
    out.push(-Fq::ONE);
    out
}

fn check_binary<F: PocField>(a: &F::Ark, b: &F::Ark, tally: &mut u64) {
    let (fa, fb) = (F::from_ark(a), F::from_ark(b));
    let ctx = || format!("{} a={a} b={b}", F::NAME);
    assert_eq!(fa.to_ark(), *a, "roundtrip {}", ctx());
    assert_eq!(fa.add(&fb).to_ark(), *a + b, "add {}", ctx());
    assert_eq!(fa.sub(&fb).to_ark(), *a - b, "sub {}", ctx());
    assert_eq!(fb.sub(&fa).to_ark(), *b - a, "sub' {}", ctx());
    assert_eq!(fa.mul(&fb).to_ark(), *a * b, "mul {}", ctx());
    assert_eq!(fa.square().to_ark(), a.square(), "square {}", ctx());
    assert_eq!(fa.double().to_ark(), a.double(), "double {}", ctx());
    assert_eq!(fa.neg().to_ark(), -*a, "neg {}", ctx());
    assert_eq!(fa.equals(&fb), a == b, "equals {}", ctx());
    assert!(fa.equals(&fa), "self-equals {}", ctx());
    assert_eq!(fa.is_zero(), a.is_zero(), "is_zero {}", ctx());
    // Results of operations (possibly weakly reduced) must compare correctly.
    assert!(fa.add(&fb).sub(&fb).equals(&fa), "add-sub equals {}", ctx());
    assert!(fa.sub(&fa).is_zero(), "a-a is_zero {}", ctx());
    *tally += 13;
}

pub fn random_values<F: PocField>(rng: &mut StdRng, count: usize) -> u64
where
    F::Ark: UniformRand,
{
    let mut n = 0;
    for i in 0..count {
        let a = F::Ark::rand(rng);
        let b = F::Ark::rand(rng);
        check_binary::<F>(&a, &b, &mut n);
        if i % 64 == 0 {
            let fa = F::from_ark(&a);
            if !a.is_zero() {
                assert_eq!(
                    fa.inverse().to_ark(),
                    a.inverse().unwrap(),
                    "{} inverse",
                    F::NAME
                );
                n += 1;
            }
        }
    }
    n
}

pub fn edge_values<F: PocField<Ark = Fq>>(rng: &mut StdRng) -> u64 {
    let mut edges = edge_elements();
    edges.extend((0..8).map(|_| Fq::rand(rng)));
    edge_pairs::<F>(&edges)
}

/// Fq2 edges: every pairing of a subset of the Fq edges as (c0, c1).
pub fn fq2_edge_values<F: PocField<Ark = Fq2>>(rng: &mut StdRng) -> u64 {
    let mut base = edge_elements();
    base.extend((0..4).map(|_| Fq::rand(rng)));
    let picked: Vec<Fq> = base.iter().step_by(3).copied().collect();
    let mut edges = Vec::new();
    for c0 in &picked {
        for c1 in &picked {
            edges.push(Fq2::new(*c0, *c1));
        }
    }
    let edges: Vec<Fq2> = edges.into_iter().step_by(7).collect();
    edge_pairs::<F>(&edges)
}

fn edge_pairs<F: PocField>(edges: &[F::Ark]) -> u64 {
    let mut n = 0;
    for a in edges {
        for b in edges {
            check_binary::<F>(a, b, &mut n);
        }
    }
    n
}

/// Long random chains of mixed operations over a small register file,
/// mirrored in arkworks and compared after every step. Intermediates stay in
/// the representation (never re-imported), so weakly reduced values flow
/// into every operation.
pub fn chains<F: PocField>(rng: &mut StdRng, steps: usize) -> u64
where
    F::Ark: UniformRand,
{
    const REGS: usize = 8;
    let mut ark: Vec<F::Ark> = (0..REGS).map(|_| F::Ark::rand(rng)).collect();
    ark[0] = F::Ark::ZERO;
    ark[1] = -F::Ark::ONE;
    let mut ours: Vec<F> = ark.iter().map(F::from_ark).collect();
    let mut n = 0;
    for step in 0..steps {
        let (d, a, b) = (
            rng.gen_range(0..REGS),
            rng.gen_range(0..REGS),
            rng.gen_range(0..REGS),
        );
        let op = rng.gen_range(0..8u32);
        let (x, y) = (ours[a], ours[b]);
        let (xa, ya) = (ark[a], ark[b]);
        let (r, ra) = match op {
            0 => (x.add(&y), xa + ya),
            1 => (x.sub(&y), xa - ya),
            2 => (x.mul(&y), xa * ya),
            3 => (x.square(), xa.square()),
            4 => (x.double(), xa.double()),
            5 => (x.neg(), -xa),
            6 => (x.mul(&x.add(&y)), xa * (xa + ya)),
            _ => {
                // Occasionally collapse to zero or reload a fresh value.
                if step % 3 == 0 {
                    (x.sub(&x), F::Ark::ZERO)
                } else {
                    let v = F::Ark::rand(rng);
                    (F::from_ark(&v), v)
                }
            }
        };
        ours[d] = r;
        ark[d] = ra;
        assert_eq!(r.to_ark(), ra, "{} chain step {step} op {op}", F::NAME);
        assert_eq!(
            r.is_zero(),
            ra.is_zero(),
            "{} chain is_zero step {step}",
            F::NAME
        );
        assert_eq!(
            r.equals(&ours[a]),
            ra == ark[a],
            "{} chain equals step {step}",
            F::NAME
        );
        n += 3;
    }
    n
}

/// Raw 9x29 inputs: `weak` are valid for every operation (value < 2p,
/// normalized limbs, including both encodings x and x + p); `mul_inputs`
/// adds values up to 2^257 - 1 and unnormalized limbs below 2^30, which only
/// multiplication and squaring accept.
pub fn u29x9_sets(rng: &mut StdRng) -> (Vec<[u32; 9]>, Vec<[u32; 9]>) {
    let p = int_from_bigint(&Fq::MODULUS);
    let two_p = biguint_add(p, p);
    let one = pow2(0);
    // Weakly reduced: [0, 2p), normalized limbs.
    let mut weak: Vec<[u64; 4]> = boundary_integers();
    for base in [p, biguint_sub(two_p, one)] {
        weak.push(base);
        weak.push(biguint_sub(base, one));
        weak.push(biguint_sub(base, pow2(1)));
    }
    weak.push(biguint_add(p, one));
    weak.push(biguint_add(p, pow2(29)));
    for _ in 0..8 {
        let r = Fq::rand(rng).into_bigint().0;
        weak.push(r);
        weak.push(biguint_add(r, p)); // the other encoding of the same value
    }
    weak.retain(|x| BigInt(*x) < BigInt(two_p));
    let weak: Vec<[u32; 9]> = weak.iter().map(|x| int_to_29(x)).collect();

    // Multiplication-only inputs: values below 2^257 (needs a 5th word).
    let mut wide: Vec<[u32; 9]> = Vec::new();
    let top = |hi: u32| {
        let mut l = [u29x9::MASK; 9];
        l[8] = hi;
        l
    };
    wide.push(top((1 << 25) - 1)); // 2^257 - 1
    wide.push(top(1 << 24)); // just above 2^256
    let mut eight_p = [0u32; 9];
    let mut acc = [0u64; 9];
    for (i, &l) in u29x9::P.iter().enumerate() {
        acc[i] = 8 * l as u64;
    }
    let mut c = 0u64;
    for i in 0..9 {
        let v = acc[i] + c;
        eight_p[i] = (v & ((1 << 29) - 1)) as u32;
        c = v >> 29;
    }
    wide.push(eight_p);
    // Unnormalized limbs (< 2^30): limb-wise sums of two weakly reduced values.
    let mut lazy: Vec<[u32; 9]> = Vec::new();
    for i in 0..weak.len() {
        let j = (i * 7 + 3) % weak.len();
        let mut s = [0u32; 9];
        for k in 0..9 {
            s[k] = weak[i][k] + weak[j][k];
        }
        lazy.push(s);
    }
    lazy.push([
        (1 << 30) - 1,
        (1 << 30) - 1,
        (1 << 30) - 1,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    {
        let mut l = [(1 << 30) - 1; 9];
        l[8] = (1 << 24) - 1; // keeps the value below 2^257
        lazy.push(l);
    }

    let mut inputs = weak.clone();
    inputs.extend(wide);
    inputs.extend(lazy);
    (weak, inputs)
}

/// Raw-limb checks for the 9x29 representation: constants, weakly reduced
/// values in [p, 2p) (two encodings of one element), values up to 2^257 and
/// unnormalized limbs below 2^30 fed to mul/square.
pub fn u29x9_raw(rng: &mut StdRng) -> u64 {
    let mut n = 0;
    // Constants.
    assert_eq!(
        Fq::from_le_bytes_mod_order(&limbs_to_bytes(&u29x9::P, 29)),
        Fq::ZERO
    );
    assert_eq!(
        limbs_to_bytes(&u29x9::P, 29)[..32],
        Fq::MODULUS.to_bytes_le()[..]
    );
    let p0 = u29x9::P[0] as u64;
    assert_eq!(
        (p0.wrapping_mul(u29x9::MU as u64) + 1) & ((1 << 29) - 1),
        0,
        "mu"
    );
    assert_eq!(U29x9::one().to_ark(), Fq::ONE);
    assert_eq!(U29x9::zero().to_ark(), Fq::ZERO);
    n += 5;

    let (weak, inputs) = u29x9_sets(rng);
    let reference = |l: &[u32; 9]| raw_to_ark(l, 29);
    // Ops over weakly reduced pairs.
    for a in &weak {
        for b in &weak {
            let (x, y) = (U29x9(*a), U29x9(*b));
            let (xa, ya) = (reference(a), reference(b));
            assert_eq!(x.to_ark(), xa, "to_ark raw {a:x?}");
            assert_eq!(x.add(&y).to_ark(), xa + ya, "raw add {a:x?} {b:x?}");
            assert_eq!(x.sub(&y).to_ark(), xa - ya, "raw sub {a:x?} {b:x?}");
            assert_eq!(x.mul(&y).to_ark(), xa * ya, "raw mul {a:x?} {b:x?}");
            assert_eq!(x.square().to_ark(), xa.square(), "raw sqr {a:x?}");
            assert_eq!(x.neg().to_ark(), -xa, "raw neg {a:x?}");
            assert_eq!(x.equals(&y), xa == ya, "raw equals {a:x?} {b:x?}");
            assert_eq!(x.is_zero(), xa.is_zero(), "raw is_zero {a:x?}");
            for r in [x.add(&y), x.sub(&y), x.mul(&y), x.square(), x.neg()] {
                assert!(r.0.iter().all(|&l| l <= u29x9::MASK), "limb bound");
                assert!(normalized_lt(&r.0, &u29x9::P2), "weak reduction bound");
            }
            n += 10;
        }
    }
    // mul/square on wide and lazy inputs.
    for a in &inputs {
        for b in &inputs {
            let r = u29x9::mont_mul(a, b);
            assert_eq!(r, u29x9::mont_mul_ref(a, b), "generated mul != loop form");
            assert_eq!(
                raw_to_ark(&r, 29),
                reference(a) * reference(b),
                "wide/lazy mul {a:x?} {b:x?}"
            );
            assert!(r.iter().all(|&l| l <= u29x9::MASK), "wide/lazy limb bound");
            assert!(normalized_lt(&r, &u29x9::P2), "wide/lazy mul result bound");
            n += 2;
        }
        let r = u29x9::mont_sqr(a);
        assert_eq!(r, u29x9::mont_sqr_ref(a), "generated sqr != loop form");
        assert_eq!(
            raw_to_ark(&r, 29),
            reference(a).square(),
            "wide/lazy sqr {a:x?}"
        );
        n += 1;
    }
    n
}

/// `a < b` for normalized 29-bit limbs.
fn normalized_lt(a: &[u32; 9], b: &[u32; 9]) -> bool {
    for i in (0..9).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// Raw-limb checks for the 8x32 representation: constants and limb-boundary
/// Montgomery forms.
pub fn u32x8_raw() -> u64 {
    let mut bytes = Vec::new();
    for l in u32x8::P {
        bytes.extend(l.to_le_bytes());
    }
    assert_eq!(bytes, Fq::MODULUS.to_bytes_le());
    assert_eq!(
        (u32x8::P[0] as u64 * u32x8::MU as u64 + 1) & 0xffff_ffff,
        0,
        "mu"
    );
    assert_eq!(U32x8::one().to_ark(), Fq::ONE);
    assert_eq!(U32x8::zero().to_ark(), Fq::ZERO);
    4
}

/// Batch-affine MSM against arkworks' `VariableBaseMSM`, including the
/// adversarial inputs from production's tests (repeated bases, P and -P,
/// identities, all-equal and complementary scalars) with tiny batches so
/// deferral, retry and XYZZ spill all run.
pub fn msm_cases<C, F, A>(rng: &mut StdRng, size: usize) -> u64
where
    C: SWCurveConfig<BaseField = F::Ark, ScalarField = Fr>,
    F: PocField,
    A: msm::BatchApply<C, F>,
{
    let mut n = 0;
    let p = Projective::<C>::rand(rng).into_affine();
    let q = Projective::<C>::rand(rng).into_affine();
    let random = random_scalars(size, rng);
    let modulus_minus_one = {
        let mut v = Fr::MODULUS;
        v.sub_with_borrow(&BigInt::from(1_u64));
        v
    };
    let mut pairs = random.clone();
    let mut complements = random.clone();
    for i in (1..size).step_by(2) {
        pairs[i] = pairs[i - 1];
        complements[i] = (-Fr::from_bigint(random[i - 1]).unwrap()).into_bigint();
    }
    let edges: Vec<BigInt<4>> = (0..size)
        .map(|i| match i % 4 {
            0 => modulus_minus_one,
            1 => BigInt::from(0_u64),
            2 => BigInt::from(1_u64),
            _ => random[i],
        })
        .collect();
    let scalar_sets = [
        random.clone(),
        vec![random[0]; size],
        vec![BigInt::from(1_u64); size],
        vec![BigInt::from(0_u64); size],
        pairs,
        complements,
        edges,
    ];
    let base_sets = [
        vec![p; size],
        (0..size).map(|i| if i % 2 == 0 { p } else { -p }).collect(),
        (0..size)
            .map(|i| [p, p, -p, -p, q, Affine::<C>::identity()][i % 6])
            .collect(),
        vec![Affine::<C>::identity(); size],
        random_bases::<C>(size, rng),
    ];
    for scalars in &scalar_sets {
        for bases in &base_sets {
            let expected = Projective::<C>::msm_bigint(bases, scalars);
            let converted = msm::convert_bases::<C, F>(bases);
            for width in [4, 9] {
                for batch in [1, 3, msm::batch_size(width)] {
                    let got = msm::msm::<C, F, A>(
                        &converted,
                        scalars,
                        width,
                        batch,
                        &mut Stats::default(),
                        &mut Phases::default(),
                    );
                    assert_eq!(
                        got,
                        expected,
                        "{}/{} msm width={width} batch={batch}",
                        F::NAME,
                        A::NAME
                    );
                    n += 1;
                }
            }
        }
    }
    n
}

/// Every width production supports (3..=16) on random inputs, with the
/// production batch size.
pub fn msm_width_sweep<C, F, A>(rng: &mut StdRng, size: usize) -> u64
where
    C: SWCurveConfig<BaseField = F::Ark, ScalarField = Fr>,
    F: PocField,
    A: msm::BatchApply<C, F>,
{
    let scalars = random_scalars(size, rng);
    let bases = random_bases::<C>(size, rng);
    let expected = Projective::<C>::msm_bigint(&bases, &scalars);
    let converted = msm::convert_bases::<C, F>(&bases);
    for width in 3..=16 {
        let got = msm::msm::<C, F, A>(
            &converted,
            &scalars,
            width,
            msm::batch_size(width),
            &mut Stats::default(),
            &mut Phases::default(),
        );
        assert_eq!(
            got,
            expected,
            "{}/{} width sweep w{width}",
            F::NAME,
            A::NAME
        );
    }
    14
}

pub fn random_scalars(size: usize, rng: &mut impl Rng) -> Vec<BigInt<4>> {
    (0..size).map(|_| Fr::rand(rng).into_bigint()).collect()
}

/// Distinct, unstructured bases: `start + i * step` (as production's tests).
pub fn random_bases<C: SWCurveConfig<ScalarField = Fr>>(
    size: usize,
    rng: &mut impl Rng,
) -> Vec<Affine<C>> {
    let step = Projective::<C>::generator() * Fr::rand(rng);
    let mut point = Projective::<C>::generator() * Fr::rand(rng);
    let mut points = Vec::with_capacity(size);
    for _ in 0..size {
        points.push(point);
        point += step;
    }
    Projective::<C>::normalize_batch(&points)
}

/// Every differential test for the scalar representations.
pub fn run_all(seed: u64, random: usize, chain: usize, msm_size: usize) -> Tally {
    let mut tally = Tally::default();
    let mut rng = StdRng::seed_from_u64(seed);
    tally.section("u32x8 constants", u32x8_raw());
    tally.section("u29x9 raw limbs (weak, wide, lazy)", u29x9_raw(&mut rng));
    tally.section("u32x8 edge pairs", edge_values::<U32x8>(&mut rng));
    tally.section("u29x9 edge pairs", edge_values::<U29x9>(&mut rng));
    tally.section("u32x8 random", random_values::<U32x8>(&mut rng, random));
    tally.section("u29x9 random", random_values::<U29x9>(&mut rng, random));
    tally.section("u32x8 chains", chains::<U32x8>(&mut rng, chain));
    tally.section("u29x9 chains", chains::<U29x9>(&mut rng, chain));
    tally.section(
        "fq2-u29x9 edge pairs",
        fq2_edge_values::<Fq2Of<U29x9>>(&mut rng),
    );
    tally.section(
        "fq2-u29x9 random",
        random_values::<Fq2Of<U29x9>>(&mut rng, random / 4),
    );
    tally.section(
        "fq2-u29x9 chains",
        chains::<Fq2Of<U29x9>>(&mut rng, chain / 4),
    );
    if msm_size > 0 {
        type G1 = ark_bn254::g1::Config;
        type G2 = ark_bn254::g2::Config;
        type S = msm::ScalarApply;
        let r = &mut rng;
        tally.section(
            "msm g1 ark adversarial",
            msm_cases::<G1, Ark, S>(r, msm_size),
        );
        tally.section(
            "msm g1 u32x8 adversarial",
            msm_cases::<G1, U32x8, S>(r, msm_size),
        );
        tally.section(
            "msm g1 u29x9 adversarial",
            msm_cases::<G1, U29x9, S>(r, msm_size),
        );
        tally.section(
            "msm g2 fq2-ark adversarial",
            msm_cases::<G2, Fq2Ark, S>(r, msm_size / 2),
        );
        tally.section(
            "msm g2 fq2-u29x9 adversarial",
            msm_cases::<G2, Fq2Of<U29x9>, S>(r, msm_size / 2),
        );
        let n = 30 * msm_size;
        tally.section(
            "msm g1 ark widths 3-16",
            msm_width_sweep::<G1, Ark, S>(r, n),
        );
        tally.section(
            "msm g1 u32x8 widths 3-16",
            msm_width_sweep::<G1, U32x8, S>(r, n),
        );
        tally.section(
            "msm g1 u29x9 widths 3-16",
            msm_width_sweep::<G1, U29x9, S>(r, n),
        );
        tally.section(
            "msm g2 fq2-u29x9 widths 3-16",
            msm_width_sweep::<G2, Fq2Of<U29x9>, S>(r, n / 4),
        );
    }
    tally
}
