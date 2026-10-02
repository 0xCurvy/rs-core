//! Microbenchmarks (experiment A) and MSM kernel timings (experiment C).
//! Results are returned as JSON strings so the native binary, Node and
//! Chromium report identically.

use core::hint::black_box;

use ark_bn254::{Fr, g1, g2};
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField, UniformRand, Zero};
use ark_std::rand::{SeedableRng, rngs::StdRng};

use crate::check::{random_bases, random_scalars};
use crate::clock::now_ms;
use crate::field::{Ark, PocField};
use crate::fq2::{Fq2Ark, Fq2Of};
use crate::msm::{self, Phases, Stats};
use crate::u29x9::U29x9;
use crate::u32x8::U32x8;

/// Median and minimum ns per operation over `samples` timed runs of `run`,
/// which performs `ops` operations. One untimed warm-up run first.
pub fn measure(samples: usize, ops: usize, mut run: impl FnMut()) -> (f64, f64) {
    run();
    let mut v: Vec<f64> = (0..samples)
        .map(|_| {
            let t = now_ms();
            run();
            (now_ms() - t) * 1e6 / ops as f64
        })
        .collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (v[v.len() / 2], v[0])
}

fn entry(name: &str, (median, min): (f64, f64)) -> String {
    format!("\"{name}\":{{\"ns\":{median:.3},\"min\":{min:.3}}}")
}

/// Latency (dependent chain) and throughput (independent batch of 256) for
/// every operation, plus conversions and inversion.
pub fn field<F: PocField>(scale: f64, samples: usize) -> String
where
    F::Ark: UniformRand,
{
    let mut rng = StdRng::seed_from_u64(7);
    let n = |base: f64| ((base * scale) as usize).max(1000);
    const K: usize = 256;
    let a0 = F::from_ark(&F::Ark::rand(&mut rng));
    // The second operand rotates through eight values, loaded each iteration,
    // so no operand is loop-invariant (see simd_bench.rs for why it matters).
    let ys8: Vec<F> = (0..8)
        .map(|_| F::from_ark(&F::Ark::rand(&mut rng)))
        .collect();
    let mut out = Vec::new();

    macro_rules! latency {
        ($name:expr, $iters:expr, |$x:ident, $y:ident| $body:expr) => {{
            let iters = $iters;
            out.push(entry(
                $name,
                measure(samples, iters, || {
                    let mut $x = black_box(a0);
                    for k in 0..iters {
                        let $y = ys8[k & 7];
                        $x = $body;
                    }
                    black_box($x);
                }),
            ));
        }};
    }
    latency!("mul_lat", n(2e6), |x, y| x.mul(&y));
    latency!("sqr_lat", n(2e6), |x, y| {
        let _ = y;
        x.square()
    });
    latency!("add_lat", n(8e6), |x, y| x.add(&y));
    latency!("sub_lat", n(8e6), |x, y| x.sub(&y));

    let mut xs: Vec<F> = (0..K)
        .map(|_| F::from_ark(&F::Ark::rand(&mut rng)))
        .collect();
    let ys: Vec<F> = (0..K)
        .map(|_| F::from_ark(&F::Ark::rand(&mut rng)))
        .collect();
    macro_rules! throughput {
        ($name:expr, $reps:expr, |$x:ident, $y:ident| $body:expr) => {{
            let reps = $reps;
            out.push(entry(
                $name,
                measure(samples, reps * K, || {
                    for _ in 0..reps {
                        for i in 0..K {
                            let $x = xs[i];
                            let $y = &ys[i];
                            xs[i] = $body;
                        }
                    }
                    black_box(&mut xs);
                }),
            ));
        }};
    }
    throughput!("mul_thr", n(2e6) / K, |x, y| x.mul(y));
    throughput!("sqr_thr", n(2e6) / K, |x, y| {
        let _ = y;
        x.square()
    });
    throughput!("add_thr", n(8e6) / K, |x, y| x.add(y));
    throughput!("sub_thr", n(8e6) / K, |x, y| x.sub(y));

    let arks: Vec<F::Ark> = (0..K).map(|_| F::Ark::rand(&mut rng)).collect();
    let mut converted = vec![F::zero(); K];
    let reps = n(1e6) / K;
    out.push(entry(
        "from_ark",
        measure(samples, reps * K, || {
            for _ in 0..reps {
                for i in 0..K {
                    converted[i] = F::from_ark(black_box(&arks[i]));
                }
                black_box(&mut converted);
            }
        }),
    ));
    let mut back = vec![F::Ark::zero(); K];
    out.push(entry(
        "to_ark",
        measure(samples, reps * K, || {
            for _ in 0..reps {
                for i in 0..K {
                    back[i] = black_box(&xs[i]).to_ark();
                }
                black_box(&mut back);
            }
        }),
    ));
    let inv_iters = n(2e4) / if F::NAME.starts_with("fq2") { 4 } else { 1 };
    out.push(entry(
        "inverse",
        measure(samples, inv_iters, || {
            let mut x = black_box(a0);
            for _ in 0..inv_iters {
                x = x.inverse();
            }
            black_box(x);
        }),
    ));
    format!("{{\"field\":\"{}\",{}}}", F::NAME, out.join(","))
}

/// Field microbenchmarks for every scalar representation.
pub fn fields(scale: f64, samples: usize) -> String {
    #[allow(unused_mut)]
    let mut parts = vec![
        field::<Ark>(scale, samples),
        field::<U32x8>(scale, samples),
        field::<U29x9>(scale, samples),
    ];
    #[cfg(target_arch = "wasm32")]
    parts.push(crate::simd_bench::field4(scale, samples));
    parts.push(field::<Fq2Ark>(scale / 2.0, samples));
    parts.push(field::<Fq2Of<U29x9>>(scale / 2.0, samples));
    #[cfg(target_arch = "wasm32")]
    parts.push(field::<crate::fq2::Fq2Simd>(scale / 2.0, samples));
    #[cfg(target_arch = "wasm32")]
    parts.push(crate::simd_bench::field_fq2x4(scale, samples));
    format!("[{}]", parts.join(","))
}

pub enum Input {
    /// Distinct random bases and uniform random scalars.
    Random,
    /// Production's `phase_bench` input: every base is the generator and the
    /// scalars are `index * 0x9e3779b97f4a7c15 + 1`.
    Generator,
    /// Distinct random bases; each scalar is 0 with probability `zero`, 1 with
    /// probability `one`, else uniform. Matches the measured A/B/L witness
    /// scalars of the production keys (no other small values occur there).
    Witness { zero: f64, one: f64 },
}

impl Input {
    pub fn parse(text: &str) -> Self {
        let parts: Vec<&str> = text.split(':').collect();
        match parts[0] {
            "generator" => Input::Generator,
            "witness" => Input::Witness {
                zero: parts[1].parse().expect("zero fraction"),
                one: parts[2].parse().expect("one fraction"),
            },
            _ => Input::Random,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Input::Random => "random".into(),
            Input::Generator => "generator".into(),
            Input::Witness { zero, one } => format!("witness:{zero}:{one}"),
        }
    }
}

pub fn msm_input<C: SWCurveConfig<ScalarField = Fr>>(
    size: usize,
    input: &Input,
    seed: u64,
) -> (Vec<Affine<C>>, Vec<BigInt<4>>) {
    match input {
        Input::Witness { zero, one } => {
            use ark_std::rand::Rng;
            let mut rng = StdRng::seed_from_u64(seed);
            let scalars = (0..size)
                .map(|_| {
                    let r: f64 = rng.r#gen();
                    if r < *zero {
                        BigInt::from(0u64)
                    } else if r < zero + one {
                        BigInt::from(1u64)
                    } else {
                        Fr::rand(&mut rng).into_bigint()
                    }
                })
                .collect();
            (random_bases::<C>(size, &mut rng), scalars)
        }
        Input::Random => {
            let mut rng = StdRng::seed_from_u64(seed);
            let scalars = random_scalars(size, &mut rng);
            (random_bases::<C>(size, &mut rng), scalars)
        }
        Input::Generator => (
            vec![Affine::<C>::generator(); size],
            (0..size)
                .map(|index| {
                    Fr::from(
                        (index as u64)
                            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                            .wrapping_add(1),
                    )
                    .into_bigint()
                })
                .collect(),
        ),
    }
}

/// Time one representation's kernel at the given widths; assert every result.
pub fn msm_field<C, F, A>(
    bases: &[Affine<C>],
    scalars: &[BigInt<4>],
    widths: &[usize],
    reps: usize,
    expected: &Projective<C>,
) -> String
where
    C: SWCurveConfig<BaseField = F::Ark, ScalarField = Fr>,
    F: PocField,
    F::Ark: UniformRand,
    A: msm::BatchApply<C, F>,
{
    let started = now_ms();
    let converted = msm::convert_bases::<C, F>(bases);
    let convert_ms = now_ms() - started;
    // ns per kernel inversion (conversion to arkworks, inversion, conversion back).
    let mut rng = StdRng::seed_from_u64(99);
    let inv_input = F::from_ark(&F::Ark::rand(&mut rng));
    let (inv_ns, _) = measure(5, 2000, || {
        let mut x = black_box(inv_input);
        for _ in 0..2000 {
            x = x.inverse();
        }
        black_box(x);
    });
    let mut rows = Vec::new();
    for &width in widths {
        let mut times = Vec::new();
        let mut stats = Stats::default();
        let mut phases = Phases::default();
        for _ in 0..reps {
            stats = Stats::default();
            phases = Phases::default();
            let t = now_ms();
            let result = msm::msm::<C, F, A>(
                &converted,
                scalars,
                width,
                msm::batch_size(width),
                &mut stats,
                &mut phases,
            );
            times.push(now_ms() - t);
            assert_eq!(
                result,
                *expected,
                "{}/{} msm w{width} != arkworks",
                F::NAME,
                A::NAME
            );
        }
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = times[times.len() / 2];
        let inv_ms = stats.inversions as f64 * inv_ns / 1e6;
        rows.push(format!(
            "{{\"width\":{width},\"ms\":{median:.3},\"min_ms\":{:.3},\"accumulate_ms\":{:.3},\"reduce_ms\":{:.3},\"combine_ms\":{:.3},\"inversions\":{},\"inversion_ms\":{inv_ms:.3},\"inversion_share\":{:.4},\"adds\":{},\"doubles\":{},\"cancels\":{},\"overflow_adds\":{},\"verified\":true}}",
            times[0],
            phases.accumulate,
            phases.reduce,
            phases.combine,
            stats.inversions,
            inv_ms / median,
            stats.adds,
            stats.doubles,
            stats.cancels,
            stats.overflow_adds
        ));
    }
    format!(
        "{{\"field\":\"{}\",\"apply\":\"{}\",\"convert_bases_ms\":{convert_ms:.3},\"inverse_ns\":{inv_ns:.1},\"widths\":[{}]}}",
        F::NAME,
        A::NAME,
        rows.join(",")
    )
}

/// Experiment C: every representation at every width on one input, each
/// result asserted equal to arkworks' `VariableBaseMSM`.
pub fn msm_all(
    curve: &str,
    size: usize,
    widths: &[usize],
    fields: &[&str],
    input: Input,
    reps: usize,
) -> String {
    let seed = 0x5eed + size as u64;
    let started = now_ms();
    let mut parts = Vec::new();
    let (setup_ms, ark_msm_ms);
    if curve == "g2" {
        let (bases, scalars) = msm_input::<g2::Config>(size, &input, seed);
        setup_ms = now_ms() - started;
        let started = now_ms();
        let expected = Projective::<g2::Config>::msm_bigint(&bases, &scalars);
        ark_msm_ms = now_ms() - started;
        let (b, s, e) = (&bases, &scalars, &expected);
        for &field in fields {
            parts.push(match field {
                "ark" => msm_field::<_, Fq2Ark, msm::ScalarApply>(b, s, widths, reps, e),
                "u29x9" => msm_field::<_, Fq2Of<U29x9>, msm::ScalarApply>(b, s, widths, reps, e),
                #[cfg(target_arch = "wasm32")]
                "simd" => {
                    type F2 = crate::fq2::Fq2Simd;
                    msm_field::<_, F2, crate::simd_msm::SimdApply<F2>>(b, s, widths, reps, e)
                }
                other => panic!("unknown G2 field {other}"),
            });
        }
    } else {
        let (bases, scalars) = msm_input::<g1::Config>(size, &input, seed);
        setup_ms = now_ms() - started;
        let started = now_ms();
        let expected = Projective::<g1::Config>::msm_bigint(&bases, &scalars);
        ark_msm_ms = now_ms() - started;
        let (b, s, e) = (&bases, &scalars, &expected);
        for &field in fields {
            parts.push(match field {
                "ark" => msm_field::<_, Ark, msm::ScalarApply>(b, s, widths, reps, e),
                "u32x8" => msm_field::<_, U32x8, msm::ScalarApply>(b, s, widths, reps, e),
                "u29x9" => msm_field::<_, U29x9, msm::ScalarApply>(b, s, widths, reps, e),
                #[cfg(target_arch = "wasm32")]
                "simd" => {
                    msm_field::<_, U29x9, crate::simd_msm::SimdApply<U29x9>>(b, s, widths, reps, e)
                }
                other => panic!("unknown G1 field {other}"),
            });
        }
    }
    let input_name = input.name();
    format!(
        "{{\"curve\":\"{curve}\",\"points\":{size},\"input\":\"{input_name}\",\"setup_ms\":{setup_ms:.1},\"ark_variable_base_msm_ms\":{ark_msm_ms:.1},\"fields\":[{}]}}",
        parts.join(",")
    )
}
