//! Development checks of the SIMD kernel, run inside a `wasm-simd-selftest`
//! WASM build by scripts/simd-selftest.mjs:
//!
//! - [`self_test`] (`simdMsmSelfTest`): the kernel against arkworks'
//!   `VariableBaseMSM` on random inputs at every width 3..=16, and on
//!   production's adversarial inputs (repeated bases, P and -P, identities,
//!   all-equal / zero / one / complementary / edge scalars) with batch sizes
//!   1, 3 and default;
//! - [`field_stress`] and [`msm_stress`] (`simdFieldStress`,
//!   `simdMsmStress`): one randomized differential round per seed, for the
//!   runner's time-bounded stress mode;
//! - [`MsmBench`] (`SimdMsmBench`): the kernel and the arkworks batch-affine
//!   path on the same input, for the runner's relative performance gate.

use ark_bn254::{Fq, Fq2, Fr, G1Projective, G2Projective, g1, g2};
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, BigInt, BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};

use super::field::PocField;
use super::fq2::Fq2Simd;
use super::kernel::{self, BatchApply, Stats};
use super::lanes::Lanes4;
use super::simd_msm::SimdApply;
use super::u29x9::{P, U29x9, canonical};

fn run<C, F, A>(bases: &[Affine<C>], scalars: &[BigInt<4>], width: usize, batch: usize)
where
    C: SWCurveConfig<BaseField = F::Ark, ScalarField = Fr>,
    F: PocField,
    A: BatchApply<C, F>,
{
    let expected = Projective::<C>::msm_bigint(bases, scalars);
    let converted = kernel::convert_bases::<C, F>(bases);
    let got = kernel::msm::<C, F, A>(&converted, scalars, width, batch, &mut Stats::default());
    assert_eq!(
        got,
        expected,
        "SIMD MSM width={width} batch={batch} size={}",
        bases.len()
    );
}

fn random_bases<C: SWCurveConfig<ScalarField = Fr>>(
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

fn cases<C, F, A>(rng: &mut StdRng, size: usize) -> u32
where
    C: SWCurveConfig<BaseField = F::Ark, ScalarField = Fr>,
    F: PocField,
    A: BatchApply<C, F>,
{
    let mut n = 0;
    let random: Vec<BigInt<4>> = (0..size).map(|_| Fr::rand(rng).into_bigint()).collect();
    // Every width on random inputs.
    let sweep = random_bases::<C>(size * 30, rng);
    let sweep_scalars: Vec<BigInt<4>> = (0..size * 30)
        .map(|_| Fr::rand(rng).into_bigint())
        .collect();
    for width in 3..=16 {
        run::<C, F, A>(&sweep, &sweep_scalars, width, kernel::batch_size(width));
        n += 1;
    }
    // Adversarial inputs.
    let p = Projective::<C>::rand(rng).into_affine();
    let q = Projective::<C>::rand(rng).into_affine();
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
            for width in [4, 9] {
                for batch in [1, 3, kernel::batch_size(width)] {
                    run::<C, F, A>(bases, scalars, width, batch);
                    n += 1;
                }
            }
        }
    }
    n
}

/// Returns the number of MSMs compared; panics on the first mismatch.
pub(crate) fn self_test(size: usize, seed: u64) -> u32 {
    let mut rng = StdRng::seed_from_u64(seed);
    let g1 = cases::<ark_bn254::g1::Config, U29x9, SimdApply<U29x9>>(&mut rng, size);
    let g2 =
        cases::<ark_bn254::g2::Config, Fq2Simd, SimdApply<Fq2Simd>>(&mut rng, size.div_ceil(2));
    g1 + g2
}

/// An arkworks Fq: uniform, or an edge value (0, +-1, +-2, small, 2^k).
fn fq_sample(rng: &mut StdRng) -> Fq {
    match rng.gen_range(0..10) {
        0 => Fq::zero(),
        1 => Fq::one(),
        2 => -Fq::one(),
        3 => Fq::from(2_u64),
        4 => -Fq::from(2_u64),
        5 => Fq::from(rng.r#gen::<u32>()),
        6 => Fq::from(2_u64).pow([rng.gen_range(0..300_u64)]),
        _ => Fq::rand(rng),
    }
}

/// `x`, or its other weakly reduced representative (`x + p < 2p`): every
/// operation must accept both.
fn weak(x: U29x9, rng: &mut StdRng) -> U29x9 {
    let c = canonical(&x.0);
    if rng.gen_bool(0.5) {
        return U29x9(c);
    }
    let mut out = [0_u32; 9];
    let mut carry = 0;
    for i in 0..9 {
        let v = c[i] + P[i] + carry;
        out[i] = v & ((1 << 29) - 1);
        carry = v >> 29;
    }
    U29x9(out)
}

/// The limb-wise sum of two normalized values without carry propagation:
/// limbs up to 2^30 - 1, value below 4p. Multiplication accepts it (the
/// relaxation documented in u29x9.rs).
fn unnormalized_sum(a: &U29x9, b: &U29x9) -> U29x9 {
    U29x9(core::array::from_fn(|i| a.0[i] + b.0[i]))
}

fn expect<T: PartialEq + core::fmt::Debug>(got: T, want: T, what: &str) -> Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{what}: got {got:?}, want {want:?}"))
    }
}

/// One randomized differential round of the kernel's field arithmetic
/// against arkworks: `U29x9` (Fq) and `Fq2Simd` (Fq2) operations on both
/// weakly reduced representatives and on edge values, chains of operations
/// that keep values lazily reduced, unnormalized multiplication inputs, and
/// every 4-lane operation (`mul4`, `sqr4`, `add4`, `sub4`, `zero_lanes`,
/// `select`) lane by lane. Returns the number of operations compared.
pub(crate) fn field_stress(seed: u64, rounds: usize) -> Result<u32, String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut n = 0;
    for _ in 0..rounds {
        let (a, b, c) = (
            fq_sample(&mut rng),
            fq_sample(&mut rng),
            fq_sample(&mut rng),
        );
        let ua = weak(U29x9::from_ark(&a), &mut rng);
        let ub = weak(U29x9::from_ark(&b), &mut rng);
        let uc = weak(U29x9::from_ark(&c), &mut rng);
        let label = |op: &str| format!("Fq {op} (seed {seed}): a={a}, b={b}");
        expect(ua.to_ark(), a, &label("round trip"))?;
        expect(ua.mul(&ub).to_ark(), a * b, &label("mul"))?;
        expect(ua.square().to_ark(), a.square(), &label("square"))?;
        expect(ua.add(&ub).to_ark(), a + b, &label("add"))?;
        expect(ua.sub(&ub).to_ark(), a - b, &label("sub"))?;
        expect(ua.double().to_ark(), a.double(), &label("double"))?;
        expect(ua.neg().to_ark(), -a, &label("neg"))?;
        expect(ua.is_zero(), a.is_zero(), &label("is_zero"))?;
        expect(ua.equals(&ub), a == b, &label("equals"))?;
        expect(ua.equals(&weak(ua, &mut rng)), true, &label("equals self"))?;
        let sum = unnormalized_sum(&ua, &ub);
        expect(
            sum.mul(&uc).to_ark(),
            (a + b) * c,
            &label("mul unnormalized"),
        )?;
        expect(
            sum.square().to_ark(),
            (a + b).square(),
            &label("sqr unnormalized"),
        )?;
        if !a.is_zero() {
            expect(
                ua.inverse().to_ark(),
                a.inverse().unwrap(),
                &label("inverse"),
            )?;
        }
        n += 13;

        // A chain of operations on lazily reduced values.
        let (mut x, mut ax) = (ua, a);
        for _ in 0..16 {
            let (y, ay) = {
                let ay = fq_sample(&mut rng);
                (weak(U29x9::from_ark(&ay), &mut rng), ay)
            };
            match rng.gen_range(0..5) {
                0 => (x, ax) = (x.mul(&y), ax * ay),
                1 => (x, ax) = (x.square(), ax.square()),
                2 => (x, ax) = (x.add(&y), ax + ay),
                3 => (x, ax) = (x.sub(&y), ax - ay),
                _ => (x, ax) = (x.add(&x.double()).mul(&y), (ax + ax.double()) * ay),
            }
        }
        expect(x.to_ark(), ax, &format!("Fq chain (seed {seed})"))?;
        n += 1;

        // Four lanes against the scalar results.
        let e: [Fq; 4] = core::array::from_fn(|_| fq_sample(&mut rng));
        let f: [Fq; 4] = core::array::from_fn(|_| fq_sample(&mut rng));
        let ue: [U29x9; 4] = core::array::from_fn(|l| weak(U29x9::from_ark(&e[l]), &mut rng));
        let uf: [U29x9; 4] = core::array::from_fn(|l| weak(U29x9::from_ark(&f[l]), &mut rng));
        let (ve, vf) = (U29x9::pack(&ue), U29x9::pack(&uf));
        let lanes = |v: &<U29x9 as Lanes4>::V| U29x9::unpack(v).map(|x| x.to_ark());
        expect(
            lanes(&U29x9::mul4(&ve, &vf)),
            core::array::from_fn(|l| e[l] * f[l]),
            "Fq mul4",
        )?;
        expect(lanes(&U29x9::sqr4(&ve)), e.map(|x| x.square()), "Fq sqr4")?;
        expect(
            lanes(&U29x9::add4(&ve, &vf)),
            core::array::from_fn(|l| e[l] + f[l]),
            "Fq add4",
        )?;
        expect(
            lanes(&U29x9::sub4(&ve, &vf)),
            core::array::from_fn(|l| e[l] - f[l]),
            "Fq sub4",
        )?;
        let sums: [U29x9; 4] = core::array::from_fn(|l| unnormalized_sum(&ue[l], &uf[l]));
        expect(
            lanes(&U29x9::mul4(&U29x9::pack(&sums), &vf)),
            core::array::from_fn(|l| (e[l] + f[l]) * f[l]),
            "Fq mul4 unnormalized",
        )?;
        let zeros = lane_set(U29x9::zero_lanes(&ve));
        expect(zeros, e.map(|x| x.is_zero()), "Fq zero_lanes")?;
        let pick: [bool; 4] = core::array::from_fn(|_| rng.r#gen());
        let mask = lane_mask(pick);
        expect(
            lanes(&U29x9::select(&ve, &vf, mask)),
            core::array::from_fn(|l| if pick[l] { e[l] } else { f[l] }),
            "Fq select",
        )?;
        n += 7;

        // Fq2 over the same base, scalar and four lanes.
        let a2 = Fq2::new(a, c);
        let b2 = Fq2::new(b, fq_sample(&mut rng));
        let (ua2, ub2) = (Fq2Simd::from_ark(&a2), Fq2Simd::from_ark(&b2));
        expect(ua2.mul(&ub2).to_ark(), a2 * b2, "Fq2 mul")?;
        expect(ua2.square().to_ark(), a2.square(), "Fq2 square")?;
        expect(ua2.sub(&ub2).to_ark(), a2 - b2, "Fq2 sub")?;
        expect(ua2.equals(&ub2), a2 == b2, "Fq2 equals")?;
        if !a2.is_zero() {
            expect(ua2.inverse().to_ark(), a2.inverse().unwrap(), "Fq2 inverse")?;
        }
        let e2: [Fq2; 4] =
            core::array::from_fn(|_| Fq2::new(fq_sample(&mut rng), fq_sample(&mut rng)));
        let f2: [Fq2; 4] =
            core::array::from_fn(|_| Fq2::new(fq_sample(&mut rng), fq_sample(&mut rng)));
        let (ve2, vf2) = (
            Fq2Simd::pack(&e2.map(|x| Fq2Simd::from_ark(&x))),
            Fq2Simd::pack(&f2.map(|x| Fq2Simd::from_ark(&x))),
        );
        let lanes2 = |v: &<Fq2Simd as Lanes4>::V| Fq2Simd::unpack(v).map(|x| x.to_ark());
        expect(
            lanes2(&Fq2Simd::mul4(&ve2, &vf2)),
            core::array::from_fn(|l| e2[l] * f2[l]),
            "Fq2 mul4",
        )?;
        expect(
            lanes2(&Fq2Simd::sqr4(&ve2)),
            e2.map(|x| x.square()),
            "Fq2 sqr4",
        )?;
        expect(
            lanes2(&Fq2Simd::add4(&ve2, &vf2)),
            core::array::from_fn(|l| e2[l] + f2[l]),
            "Fq2 add4",
        )?;
        expect(
            lanes2(&Fq2Simd::sub4(&ve2, &vf2)),
            core::array::from_fn(|l| e2[l] - f2[l]),
            "Fq2 sub4",
        )?;
        expect(
            lane_set(Fq2Simd::zero_lanes(&ve2)),
            e2.map(|x| x.is_zero()),
            "Fq2 zero_lanes",
        )?;
        n += 10;
    }
    Ok(n)
}

fn lane_mask(lanes: [bool; 4]) -> core::arch::wasm32::v128 {
    let m = |b: bool| if b { u32::MAX } else { 0 };
    core::arch::wasm32::u32x4(m(lanes[0]), m(lanes[1]), m(lanes[2]), m(lanes[3]))
}

fn lane_set(mask: core::arch::wasm32::v128) -> [bool; 4] {
    use core::arch::wasm32::u32x4_extract_lane as lane;
    [
        lane::<0>(mask) != 0,
        lane::<1>(mask) != 0,
        lane::<2>(mask) != 0,
        lane::<3>(mask) != 0,
    ]
}

/// A scalar whose every `width`-bit digit is `digit` (reduced mod r): the
/// signed recoding's carry chains.
fn repeated_digit(digit: u64, width: usize) -> BigInt<4> {
    let mut bytes = [0_u8; 32];
    for bit in 0..256 {
        if (digit >> (bit % width)) & 1 == 1 {
            bytes[bit / 8] |= 1 << (bit % 8);
        }
    }
    Fr::from_le_bytes_mod_order(&bytes).into_bigint()
}

/// One randomized MSM through the production entry (`try_msm`) against
/// arkworks' `VariableBaseMSM`: a random curve, size (log-uniform up to
/// `max_size`, G2 half), width 3..=16, batch size, and base and scalar mix
/// (distinct, few repeated points with negatives and identities; uniform,
/// small, zero/one-heavy, all equal, complementary, edge and carry-chain
/// scalars). Returns the number of MSMs compared.
pub(crate) fn msm_stress(seed: u64, max_size: usize) -> Result<u32, String> {
    let mut rng = StdRng::seed_from_u64(seed);
    if rng.gen_bool(0.5) {
        msm_case::<g1::Config>(&mut rng, max_size.max(1), seed)
    } else {
        msm_case::<g2::Config>(&mut rng, max_size.div_ceil(2).max(1), seed)
    }
}

fn msm_case<C>(rng: &mut StdRng, max_size: usize, seed: u64) -> Result<u32, String>
where
    C: SWCurveConfig<ScalarField = Fr>,
{
    let bits = rng.gen_range(0..=max_size.ilog2());
    let size = rng.gen_range(1..=(1_usize << bits).min(max_size));
    let width = rng.gen_range(3..=16);
    let batch = match rng.gen_range(0..4) {
        0 => 1,
        1 => rng.gen_range(2..=8),
        2 => rng.gen_range(9..=64),
        _ => kernel::batch_size(width),
    };
    let base_kind = rng.gen_range(0..4);
    let bases: Vec<Affine<C>> = match base_kind {
        0 => random_bases::<C>(size, rng),
        1 => {
            let pool: Vec<Affine<C>> = (0..rng.gen_range(1..=3))
                .map(|_| Projective::<C>::rand(rng).into_affine())
                .flat_map(|p| [p, -p, (p + p).into_affine()])
                .chain([Affine::<C>::identity()])
                .collect();
            (0..size)
                .map(|_| pool[rng.gen_range(0..pool.len())])
                .collect()
        }
        2 => {
            let mut bases = random_bases::<C>(size, rng);
            for i in 0..size {
                match rng.gen_range(0..8) {
                    0 => bases[i] = Affine::<C>::identity(),
                    1 if i > 0 => bases[i] = bases[rng.gen_range(0..i)],
                    2 if i > 0 => bases[i] = -bases[rng.gen_range(0..i)],
                    _ => {}
                }
            }
            bases
        }
        _ => {
            let p = Projective::<C>::rand(rng).into_affine();
            (0..size).map(|i| if i % 2 == 0 { p } else { -p }).collect()
        }
    };
    let scalar_kind = rng.gen_range(0..6);
    let half = 1_u64 << (width - 1);
    let scalars: Vec<BigInt<4>> = match scalar_kind {
        0 => (0..size).map(|_| Fr::rand(rng).into_bigint()).collect(),
        1 => (0..size)
            .map(|_| BigInt::from(rng.r#gen::<u64>() >> rng.gen_range(0..64)))
            .collect(),
        2 => (0..size)
            .map(|_| BigInt::from(rng.gen_range(0..3_u64).saturating_sub(1)))
            .collect(),
        3 => vec![Fr::rand(rng).into_bigint(); size],
        4 => {
            let mut s: Vec<Fr> = (0..size).map(|_| Fr::rand(rng)).collect();
            for i in (1..size).step_by(2) {
                s[i] = -s[i - 1];
            }
            s.into_iter().map(|x| x.into_bigint()).collect()
        }
        _ => (0..size)
            .map(|_| match rng.gen_range(0..6) {
                0 => (-Fr::one()).into_bigint(),
                1 => BigInt::from(0_u64),
                2 => BigInt::from(1_u64),
                3 => repeated_digit(half - 1, width),
                4 => repeated_digit(half, width),
                _ => Fr::from(2_u64)
                    .pow([rng.gen_range(0..254_u64)])
                    .into_bigint(),
            })
            .collect(),
    };
    let expected = Projective::<C>::msm_bigint(&bases, &scalars);
    let got = super::try_msm::<Projective<C>>(&bases, &scalars, width, batch)
        .ok_or("the SIMD dispatch did not take a BN254 curve")?;
    if got != expected {
        return Err(format!(
            "SIMD MSM mismatch (seed {seed}): {} size={size} width={width} batch={batch} bases={base_kind} scalars={scalar_kind}",
            core::any::type_name::<C>()
        ));
    }
    Ok(1)
}

/// The SIMD kernel and the arkworks batch-affine path (`msm::AffineBuckets`,
/// what production runs without `wasm-simd-msm`) on one input, at the
/// production window width and batch size for its size. The caller times
/// [`Self::simd`] and [`Self::ark`] alternately in one process; the ratio is
/// independent of the machine's speed.
pub(crate) struct MsmBench {
    g1: Option<(Vec<ark_bn254::G1Affine>, Vec<BigInt<4>>)>,
    g2: Option<(Vec<ark_bn254::G2Affine>, Vec<BigInt<4>>)>,
    width: usize,
}

impl MsmBench {
    /// `curve` 1 is G1, 2 is G2; `2^log_size` random bases and scalars.
    pub(crate) fn new(curve: u32, log_size: u32, seed: u64) -> Result<Self, String> {
        if !(4..=16).contains(&log_size) {
            return Err("log_size must be in 4..=16".into());
        }
        let mut rng = StdRng::seed_from_u64(seed);
        let size = 1_usize << log_size;
        let scalars: Vec<BigInt<4>> = (0..size)
            .map(|_| Fr::rand(&mut rng).into_bigint())
            .collect();
        #[cfg(not(feature = "parallel"))]
        let width = crate::msm::serial_window_bits(size);
        #[cfg(feature = "parallel")]
        let width = crate::msm::adaptive_window_bits(size);
        let mut bench = MsmBench {
            g1: None,
            g2: None,
            width,
        };
        match curve {
            1 => bench.g1 = Some((random_bases::<g1::Config>(size, &mut rng), scalars)),
            2 => bench.g2 = Some((random_bases::<g2::Config>(size, &mut rng), scalars)),
            _ => return Err("curve must be 1 (G1) or 2 (G2)".into()),
        }
        Ok(bench)
    }

    pub(crate) fn width(&self) -> usize {
        self.width
    }

    /// The SIMD kernel through the production entry; a checksum of the sum.
    pub(crate) fn simd(&self) -> u32 {
        let batch = crate::msm::batch_size(self.width);
        if let Some((bases, scalars)) = &self.g1 {
            let sum = super::try_msm::<G1Projective>(bases, scalars, self.width, batch);
            checksum(&sum.expect("G1 dispatch"))
        } else if let Some((bases, scalars)) = &self.g2 {
            let sum = super::try_msm::<G2Projective>(bases, scalars, self.width, batch);
            checksum(&sum.expect("G2 dispatch"))
        } else {
            unreachable!()
        }
    }

    /// The arkworks batch-affine path; a checksum of the sum.
    pub(crate) fn ark(&self) -> u32 {
        if let Some((bases, scalars)) = &self.g1 {
            checksum(&ark_batch_affine(bases, scalars, self.width))
        } else if let Some((bases, scalars)) = &self.g2 {
            checksum(&ark_batch_affine(bases, scalars, self.width))
        } else {
            unreachable!()
        }
    }

    /// Both paths against arkworks' `VariableBaseMSM`.
    pub(crate) fn check(&self) -> Result<(), String> {
        let batch = crate::msm::batch_size(self.width);
        let ok = if let Some((bases, scalars)) = &self.g1 {
            let want = G1Projective::msm_bigint(bases, scalars);
            super::try_msm::<G1Projective>(bases, scalars, self.width, batch) == Some(want)
                && ark_batch_affine(bases, scalars, self.width) == want
        } else if let Some((bases, scalars)) = &self.g2 {
            let want = G2Projective::msm_bigint(bases, scalars);
            super::try_msm::<G2Projective>(bases, scalars, self.width, batch) == Some(want)
                && ark_batch_affine(bases, scalars, self.width) == want
        } else {
            false
        };
        if ok {
            Ok(())
        } else {
            Err("benchmark MSMs disagree with arkworks".into())
        }
    }
}

fn checksum<C: SWCurveConfig>(sum: &Projective<C>) -> u32 {
    let affine = sum.into_affine();
    let mut bytes = Vec::new();
    use ark_serialize::CanonicalSerialize;
    affine
        .serialize_compressed(&mut bytes)
        .expect("serialize a point");
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// `msm::batch_affine_msm`, the arkworks path: the same windows, recoding and
/// batch-affine scheduling with arkworks field arithmetic, its windows on the
/// pool under `parallel`.
fn ark_batch_affine<C: SWCurveConfig<ScalarField = Fr>>(
    bases: &[Affine<C>],
    scalars: &[BigInt<4>],
    width: usize,
) -> Projective<C> {
    let window_sum = |window: usize| {
        let mut buckets =
            crate::msm::AffineBuckets::<C>::with_batch_size(width, crate::msm::batch_size(width));
        for (base, scalar) in bases.iter().zip(scalars) {
            buckets.add_digit(crate::msm::signed_window_digit(scalar, width, window), base);
        }
        buckets.finish();
        buckets.window_sum()
    };
    let windows = (Fr::MODULUS_BIT_SIZE as usize).div_ceil(width);
    #[cfg(feature = "parallel")]
    let sums: Vec<Projective<C>> = {
        use rayon::prelude::*;
        (0..windows).into_par_iter().map(window_sum).collect()
    };
    #[cfg(not(feature = "parallel"))]
    let sums: Vec<Projective<C>> = (0..windows).map(window_sum).collect();
    let mut total = Projective::<C>::zero();
    for sum in sums.iter().rev() {
        for _ in 0..width {
            total.double_in_place();
        }
        total += sum;
    }
    total
}
