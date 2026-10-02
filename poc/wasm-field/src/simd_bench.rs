//! Benchmarks and differential tests for the 4-way simd128 representation
//! (WASM only; it has no native build).

#![cfg(target_arch = "wasm32")]

use core::hint::black_box;

use ark_bn254::Fq;
use ark_ff::{Field, UniformRand};
use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};

use crate::bench::measure;
use crate::check::{raw_to_ark, u29x9_sets};
use crate::field::PocField;
use crate::gen_u29::mul4_split;
use crate::simd::{U29x9x4, add4, mul4, sqr4, sub4};
use crate::u29x9::U29x9;

fn entry(name: &str, (median, min): (f64, f64)) -> String {
    format!("\"{name}\":{{\"ns\":{median:.3},\"min\":{min:.3}}}")
}

fn rand4(rng: &mut StdRng) -> U29x9x4 {
    let e: Vec<U29x9> = (0..4).map(|_| U29x9::from_ark(&Fq::rand(rng))).collect();
    U29x9x4::pack([&e[0], &e[1], &e[2], &e[3]])
}

/// ns per *element* (a 4-way operation counts as four).
pub fn field4(scale: f64, samples: usize) -> String {
    let mut rng = StdRng::seed_from_u64(7);
    let n = |base: f64| ((base * scale) as usize).max(1000);
    const K: usize = 64; // 64 blocks of 4 = 256 elements, as the scalar benches
    let a0 = rand4(&mut rng);
    // Rotate the second operand (loaded each iteration): a loop-invariant
    // operand lets LLVM hoist its zero-extension out of the loop, after which
    // the backend can no longer form extmul and emits i64x2.mul instead.
    let ys8: Vec<U29x9x4> = (0..8).map(|_| rand4(&mut rng)).collect();
    let mut out = Vec::new();

    // Latency of one 4-way multiplication, divided by four.
    let iters = n(2e6) / 4;
    out.push(entry(
        "mul_lat",
        measure(samples, iters * 4, || {
            let mut x = black_box(a0);
            for k in 0..iters {
                let y = &ys8[k & 7];
                x = U29x9x4(mul4(&x.0, &y.0));
            }
            black_box(x);
        }),
    ));
    out.push(entry(
        "mul_split_lat",
        measure(samples, iters * 4, || {
            let mut x = black_box(a0);
            for k in 0..iters {
                let y = &ys8[k & 7];
                x = U29x9x4(mul4_split(&x.0, &y.0));
            }
            black_box(x);
        }),
    ));
    out.push(entry(
        "sqr_lat",
        measure(samples, iters * 4, || {
            let mut x = black_box(a0);
            for _ in 0..iters {
                x = U29x9x4(sqr4(&x.0));
            }
            black_box(x);
        }),
    ));
    let add_iters = n(8e6) / 4;
    out.push(entry(
        "add_lat",
        measure(samples, add_iters * 4, || {
            let mut x = black_box(a0);
            for k in 0..add_iters {
                let y = &ys8[k & 7];
                x = U29x9x4(add4(&x.0, &y.0));
            }
            black_box(x);
        }),
    ));
    out.push(entry(
        "sub_lat",
        measure(samples, add_iters * 4, || {
            let mut x = black_box(a0);
            for k in 0..add_iters {
                let y = &ys8[k & 7];
                x = U29x9x4(sub4(&x.0, &y.0));
            }
            black_box(x);
        }),
    ));

    let mut xs: Vec<U29x9x4> = (0..K).map(|_| rand4(&mut rng)).collect();
    let ys: Vec<U29x9x4> = (0..K).map(|_| rand4(&mut rng)).collect();
    macro_rules! throughput {
        ($name:expr, $ops:expr, |$x:ident, $y:ident| $body:expr) => {{
            let reps = $ops / (4 * K);
            out.push(entry(
                $name,
                measure(samples, reps * K * 4, || {
                    for _ in 0..reps {
                        for i in 0..K {
                            let $x = &xs[i].0;
                            let $y = &ys[i].0;
                            xs[i] = U29x9x4($body);
                        }
                    }
                    black_box(&mut xs);
                }),
            ));
        }};
    }
    throughput!("mul_thr", n(2e6), |x, y| mul4(x, y));
    throughput!("mul_split_thr", n(2e6), |x, y| mul4_split(x, y));
    throughput!("sqr_thr", n(2e6), |x, y| {
        let _ = y;
        sqr4(x)
    });
    throughput!("add_thr", n(8e6), |x, y| add4(x, y));
    throughput!("sub_thr", n(8e6), |x, y| sub4(x, y));

    // Conversions: pack four scalar u29x9 elements / unpack them again.
    let scalars: Vec<U29x9> = (0..4 * K)
        .map(|_| U29x9::from_ark(&Fq::rand(&mut rng)))
        .collect();
    let reps = n(1e6) / (4 * K);
    out.push(entry(
        "pack",
        measure(samples, reps * K * 4, || {
            for _ in 0..reps {
                for i in 0..K {
                    let e = &scalars[4 * i..4 * i + 4];
                    xs[i] = U29x9x4::pack([&e[0], &e[1], &e[2], &e[3]]);
                }
                black_box(&mut xs);
            }
        }),
    ));
    let mut unpacked = vec![U29x9([0; 9]); 4 * K];
    out.push(entry(
        "unpack",
        measure(samples, reps * K * 4, || {
            for _ in 0..reps {
                for i in 0..K {
                    let e = black_box(&xs[i]).unpack();
                    unpacked[4 * i..4 * i + 4].copy_from_slice(&e);
                }
                black_box(&mut unpacked);
            }
        }),
    ));
    format!("{{\"field\":\"simd4\",{}}}", out.join(","))
}

/// The G2 kernel's layout: four Fq2 elements per `Fq2x4` (three 4-lane base
/// multiplications per Fq2 multiplication). ns per Fq2 element.
pub fn field_fq2x4(scale: f64, samples: usize) -> String {
    use crate::fq2::Fq2Simd;
    use crate::lanes::{Fq2x4, Lanes4};
    let mut rng = StdRng::seed_from_u64(9);
    let n = |base: f64| ((base * scale) as usize).max(1000);
    const K: usize = 64;
    let mut rand4 = || -> Fq2x4 {
        let e: [Fq2Simd; 4] =
            core::array::from_fn(|_| Fq2Simd::from_ark(&ark_bn254::Fq2::rand(&mut rng)));
        Fq2Simd::pack(&e)
    };
    let mut xs: Vec<Fq2x4> = (0..K).map(|_| rand4()).collect();
    let ys: Vec<Fq2x4> = (0..K).map(|_| rand4()).collect();
    let mut out = Vec::new();
    macro_rules! throughput {
        ($name:expr, $ops:expr, |$x:ident, $y:ident| $body:expr) => {{
            let reps = ($ops / (4 * K)).max(1);
            out.push(entry(
                $name,
                measure(samples, reps * K * 4, || {
                    for _ in 0..reps {
                        for i in 0..K {
                            let $x = &xs[i];
                            let $y = &ys[i];
                            xs[i] = $body;
                        }
                    }
                    black_box(&mut xs);
                }),
            ));
        }};
    }
    throughput!("mul_thr", n(5e5), |x, y| Fq2Simd::mul4(x, y));
    throughput!("sqr_thr", n(5e5), |x, y| {
        let _ = y;
        Fq2Simd::sqr4(x)
    });
    throughput!("add_thr", n(2e6), |x, y| Fq2Simd::add4(x, y));
    throughput!("sub_thr", n(2e6), |x, y| Fq2Simd::sub4(x, y));
    format!("{{\"field\":\"fq2x4\",{}}}", out.join(","))
}

fn lanes(x: &U29x9x4) -> [Fq; 4] {
    x.unpack().map(|e| e.to_ark())
}

/// Differential tests: random lanes, the raw 9x29 edge sets in every lane
/// position, and four independent mixed-operation chains.
pub fn checks(seed: u64, random: usize, chain: usize) -> Vec<(String, u64)> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x51ad);
    let mut sections = Vec::new();

    let mut n = 0;
    for _ in 0..random.div_ceil(4) {
        let a: [Fq; 4] = core::array::from_fn(|_| Fq::rand(&mut rng));
        let b: [Fq; 4] = core::array::from_fn(|_| Fq::rand(&mut rng));
        let ea = a.map(|v| U29x9::from_ark(&v));
        let eb = b.map(|v| U29x9::from_ark(&v));
        let x = U29x9x4::pack([&ea[0], &ea[1], &ea[2], &ea[3]]);
        let y = U29x9x4::pack([&eb[0], &eb[1], &eb[2], &eb[3]]);
        let m = lanes(&U29x9x4(mul4(&x.0, &y.0)));
        let s = lanes(&U29x9x4(sqr4(&x.0)));
        let ad = lanes(&U29x9x4(add4(&x.0, &y.0)));
        let sb = lanes(&U29x9x4(sub4(&x.0, &y.0)));
        for k in 0..4 {
            assert_eq!(m[k], a[k] * b[k], "simd mul lane {k}");
            assert_eq!(s[k], a[k].square(), "simd sqr lane {k}");
            assert_eq!(ad[k], a[k] + b[k], "simd add lane {k}");
            assert_eq!(sb[k], a[k] - b[k], "simd sub lane {k}");
        }
        n += 16;
    }
    sections.push(("simd4 random".to_string(), n));

    // Raw edge sets; also require lane-for-lane identity with scalar u29x9.
    let (weak, inputs) = u29x9_sets(&mut rng);
    let mut n = 0;
    let quad = |v: &[[u32; 9]], i: usize| -> [[u32; 9]; 4] {
        core::array::from_fn(|k| v[(i + 5 * k) % v.len()])
    };
    for i in 0..inputs.len() {
        for j in 0..inputs.len() {
            let (qa, qb) = (quad(&inputs, i), quad(&inputs, j));
            let ea = qa.map(U29x9);
            let eb = qb.map(U29x9);
            let x = U29x9x4::pack([&ea[0], &ea[1], &ea[2], &ea[3]]);
            let y = U29x9x4::pack([&eb[0], &eb[1], &eb[2], &eb[3]]);
            let m = U29x9x4(mul4(&x.0, &y.0)).unpack();
            let m_ref = U29x9x4(crate::simd::mul4_ref(&x.0, &y.0)).unpack();
            let m_split = U29x9x4(mul4_split(&x.0, &y.0)).unpack();
            for k in 0..4 {
                assert_eq!(
                    m[k].0,
                    crate::u29x9::mont_mul(&qa[k], &qb[k]),
                    "simd raw mul"
                );
                assert_eq!(m[k].0, m_ref[k].0, "generated mul4 != loop form");
                assert_eq!(m[k].0, m_split[k].0, "mul4_split != mul4");
                assert_eq!(
                    raw_to_ark(&m[k].0, 29),
                    raw_to_ark(&qa[k], 29) * raw_to_ark(&qb[k], 29),
                    "simd raw mul value"
                );
            }
            n += 8;
        }
        let qa = quad(&inputs, i);
        let ea = qa.map(U29x9);
        let x = U29x9x4::pack([&ea[0], &ea[1], &ea[2], &ea[3]]);
        let s = U29x9x4(sqr4(&x.0)).unpack();
        let s_ref = U29x9x4(crate::simd::sqr4_ref(&x.0)).unpack();
        for k in 0..4 {
            assert_eq!(s[k].0, crate::u29x9::mont_sqr(&qa[k]), "simd raw sqr");
            assert_eq!(s[k].0, s_ref[k].0, "generated sqr4 != loop form");
        }
        n += 4;
    }
    for i in 0..weak.len() {
        for j in 0..weak.len() {
            let (qa, qb) = (quad(&weak, i), quad(&weak, j));
            let ea = qa.map(U29x9);
            let eb = qb.map(U29x9);
            let x = U29x9x4::pack([&ea[0], &ea[1], &ea[2], &ea[3]]);
            let y = U29x9x4::pack([&eb[0], &eb[1], &eb[2], &eb[3]]);
            let ad = U29x9x4(add4(&x.0, &y.0)).unpack();
            let sb = U29x9x4(sub4(&x.0, &y.0)).unpack();
            for k in 0..4 {
                assert_eq!(ad[k].0, ea[k].add(&eb[k]).0, "simd raw add");
                assert_eq!(sb[k].0, ea[k].sub(&eb[k]).0, "simd raw sub");
            }
            n += 8;
        }
    }
    sections.push(("simd4 raw limbs (weak, wide, lazy)".to_string(), n));

    // Four independent chains, one per lane.
    const REGS: usize = 6;
    let mut ark: Vec<[Fq; 4]> = (0..REGS)
        .map(|_| core::array::from_fn(|_| Fq::rand(&mut rng)))
        .collect();
    ark[0] = [Fq::from(0u64); 4];
    let mut ours: Vec<U29x9x4> = ark
        .iter()
        .map(|v| {
            let e = v.map(|x| U29x9::from_ark(&x));
            U29x9x4::pack([&e[0], &e[1], &e[2], &e[3]])
        })
        .collect();
    let mut n = 0;
    for step in 0..chain {
        let (d, a, b) = (
            rng.gen_range(0..REGS),
            rng.gen_range(0..REGS),
            rng.gen_range(0..REGS),
        );
        let op = rng.gen_range(0..4u32);
        let (x, y) = (ours[a].0, ours[b].0);
        let r = match op {
            0 => add4(&x, &y),
            1 => sub4(&x, &y),
            2 => mul4(&x, &y),
            _ => sqr4(&x),
        };
        let ra: [Fq; 4] = core::array::from_fn(|k| {
            let (u, v) = (ark[a][k], ark[b][k]);
            match op {
                0 => u + v,
                1 => u - v,
                2 => u * v,
                _ => u.square(),
            }
        });
        ours[d] = U29x9x4(r);
        ark[d] = ra;
        assert_eq!(lanes(&ours[d]), ra, "simd chain step {step} op {op}");
        n += 4;
    }
    sections.push(("simd4 chains".to_string(), n));
    sections
}
