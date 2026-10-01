//! Compare resident MSM bucket accumulators on deterministic BN254 inputs.
//!
//! `compare` times the pre-batch-affine configuration (XYZZ buckets with the
//! legacy window policy) against the current production path, alternating
//! their order on every sample, and checks both return the same group element.
//! `sweep` times explicit width/accumulator/batch combinations, and `profile`
//! prints a serial per-phase breakdown.
//!
//! "Serial" is a one-worker Rayon pool with the non-`parallel` window policy:
//! the resident window loop is the same code with or without the feature.

use std::{env, hint::black_box, time::Instant};

use ark_bn254::Fr;

use curvy_prover::proof_bench::{
    MsmAccumulator, MsmFixture, MsmScalars, batch_affine_batch_size, parallel_window_bits,
    serial_msm_window_bits,
};
use rayon::{ThreadPool, ThreadPoolBuilder};

const USAGE: &str = "usage:
  msm_accumulation compare <g1|g2> <log-sizes,...> <threads> [samples=7] [uniform|witness|ones]
  msm_accumulation sweep <g1|g2> <log-size> <threads> <widths,...> <accumulators,...> [samples=7] [scalars]
      accumulators: xyzz, affine, affine:<batch>, production
  msm_accumulation profile <g1|g2> <log-size> <width|serial|parallel> <xyzz|affine> [scalars]
  msm_accumulation primitives";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("compare") if (4..=6).contains(&args.len()) => compare(&args),
        Some("sweep") if (6..=8).contains(&args.len()) => sweep(&args),
        Some("profile") if (5..=6).contains(&args.len()) => profile(&args),
        Some("primitives") if args.len() == 1 => {
            primitives();
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

/// Window policy before batch-affine accumulation, kept for comparisons.
fn legacy_window_bits(points: usize, threads: usize) -> usize {
    if threads == 1 {
        if points < 32 {
            3
        } else {
            ((points.next_power_of_two().trailing_zeros() as usize * 69 / 100) + 2).min(16)
        }
    } else {
        match points {
            0..=31 => 3,
            32..=255 => 5,
            256..=1_023 => 7,
            1_024..=32_768 => 8,
            32_769..=65_536 => 9,
            65_537..=262_144 => 10,
            262_145..=524_288 => 11,
            524_289..=2_097_152 => 12,
            _ => 13,
        }
    }
}

fn production_window_bits(points: usize, threads: usize) -> usize {
    if threads == 1 {
        serial_msm_window_bits(points)
    } else {
        parallel_window_bits(points)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    G1,
    G2,
}

fn group(value: &str) -> Result<Group, Box<dyn std::error::Error>> {
    match value {
        "g1" => Ok(Group::G1),
        "g2" => Ok(Group::G2),
        _ => Err("group must be g1 or g2".into()),
    }
}

fn scalars(value: Option<&String>) -> Result<MsmScalars, Box<dyn std::error::Error>> {
    match value.map_or("uniform", String::as_str) {
        "uniform" => Ok(MsmScalars::Uniform),
        "witness" => Ok(MsmScalars::Witness),
        "ones" => Ok(MsmScalars::Ones),
        _ => Err("scalars must be uniform, witness, or ones".into()),
    }
}

fn samples(value: Option<&String>) -> Result<usize, Box<dyn std::error::Error>> {
    let samples = value.map_or(Ok(7), |value| value.parse())?;
    if samples == 0 {
        return Err("samples must be positive".into());
    }
    Ok(samples)
}

fn accumulator(value: &str) -> Result<MsmAccumulator, Box<dyn std::error::Error>> {
    Ok(match value {
        "xyzz" => MsmAccumulator::Xyzz,
        "affine" => MsmAccumulator::BatchAffine(None),
        "production" => MsmAccumulator::Production,
        _ => match value.strip_prefix("affine:") {
            Some(batch) => MsmAccumulator::BatchAffine(Some(batch.parse()?)),
            None => return Err(format!("unknown accumulator {value}").into()),
        },
    })
}

fn pool(threads: usize) -> Result<ThreadPool, Box<dyn std::error::Error>> {
    if threads == 0 {
        return Err("threads must be positive".into());
    }
    Ok(ThreadPoolBuilder::new().num_threads(threads).build()?)
}

/// One timed MSM; returns milliseconds and the result's affine coordinates
/// (`Display` normalizes, so equal group elements print identically).
fn run(
    pool: &ThreadPool,
    fixture: &MsmFixture,
    group: Group,
    accumulator: MsmAccumulator,
    width: usize,
) -> (f64, String) {
    let started = Instant::now();
    let fingerprint = pool.install(|| match group {
        Group::G1 => black_box(fixture.g1(accumulator, width)).to_string(),
        Group::G2 => black_box(fixture.g2(accumulator, width)).to_string(),
    });
    (started.elapsed().as_secs_f64() * 1_000.0, fingerprint)
}

fn median(samples: &mut [f64]) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn compare(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let group = group(&args[1])?;
    let sizes = args[2]
        .split(',')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()?;
    let threads = args[3].parse::<usize>()?;
    let samples = samples(args.get(4))?;
    let scalars = scalars(args.get(5))?;
    let pool = pool(threads)?;
    println!(
        "group\tlog_size\tthreads\tbefore_width\tafter_width\tbefore_ms\tafter_ms\tchange_pct"
    );
    for log_size in sizes {
        let fixture = MsmFixture::new(log_size, scalars, group == Group::G2);
        let points = fixture.points();
        let before_width = legacy_window_bits(points, threads);
        let after_width = production_window_bits(points, threads);
        // Warm caches and the pool; check both paths agree.
        let (_, before_result) = run(&pool, &fixture, group, MsmAccumulator::Xyzz, before_width);
        let (_, after_result) = run(
            &pool,
            &fixture,
            group,
            MsmAccumulator::Production,
            after_width,
        );
        if before_result != after_result {
            return Err(format!("results differ at 2^{log_size}").into());
        }
        let mut before = Vec::with_capacity(samples);
        let mut after = Vec::with_capacity(samples);
        for sample in 0..samples {
            let mut time_before =
                || before.push(run(&pool, &fixture, group, MsmAccumulator::Xyzz, before_width).0);
            let mut time_after = || {
                after.push(
                    run(
                        &pool,
                        &fixture,
                        group,
                        MsmAccumulator::Production,
                        after_width,
                    )
                    .0,
                )
            };
            if sample % 2 == 0 {
                time_before();
                time_after();
            } else {
                time_after();
                time_before();
            }
        }
        let (before, after) = (median(&mut before), median(&mut after));
        println!(
            "{}\t{log_size}\t{threads}\t{before_width}\t{after_width}\t{before:.3}\t{after:.3}\t{:+.1}",
            args[1],
            (after / before - 1.0) * 100.0
        );
    }
    Ok(())
}

fn sweep(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let group = group(&args[1])?;
    let log_size = args[2].parse::<u32>()?;
    let threads = args[3].parse::<usize>()?;
    let widths = args[4]
        .split(',')
        .map(str::parse::<usize>)
        .collect::<Result<Vec<_>, _>>()?;
    if widths.iter().any(|width| !(3..=16).contains(width)) {
        return Err("widths must be in 3..=16".into());
    }
    let accumulators = args[5]
        .split(',')
        .map(|value| accumulator(value).map(|parsed| (value.to_owned(), parsed)))
        .collect::<Result<Vec<_>, _>>()?;
    let samples = samples(args.get(6))?;
    let scalars = scalars(args.get(7))?;
    let pool = pool(threads)?;
    let fixture = MsmFixture::new(log_size, scalars, group == Group::G2);
    let mut cases = Vec::new();
    for &width in &widths {
        for (name, accumulator) in &accumulators {
            cases.push((
                width,
                name.clone(),
                *accumulator,
                Vec::with_capacity(samples),
            ));
        }
    }
    let mut reference = None::<String>;
    for (width, name, accumulator, _) in &cases {
        let (_, result) = run(&pool, &fixture, group, *accumulator, *width);
        if reference.get_or_insert_with(|| result.clone()) != &result {
            return Err(format!("width {width} {name} changed the result").into());
        }
    }
    for sample in 0..samples {
        let order: Box<dyn Iterator<Item = usize>> = if sample % 2 == 0 {
            Box::new(0..cases.len())
        } else {
            Box::new((0..cases.len()).rev())
        };
        for index in order {
            let (width, _, accumulator, timings) = &mut cases[index];
            timings.push(run(&pool, &fixture, group, *accumulator, *width).0);
        }
    }
    println!("group\tlog_size\tthreads\twidth\taccumulator\tbatch\tmedian_ms\tmin_ms\tmax_ms");
    for (width, name, accumulator, mut timings) in cases {
        let median = median(&mut timings);
        let batch = match accumulator {
            MsmAccumulator::BatchAffine(Some(batch)) => batch,
            MsmAccumulator::BatchAffine(None) => batch_affine_batch_size(width),
            _ => 0,
        };
        println!(
            "{}\t{log_size}\t{threads}\t{width}\t{name}\t{batch}\t{median:.3}\t{:.3}\t{:.3}",
            args[1],
            timings[0],
            timings[timings.len() - 1]
        );
    }
    Ok(())
}

fn profile(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let group = group(&args[1])?;
    let log_size = args[2].parse::<u32>()?;
    let points = 1_usize << log_size;
    let width = match args[3].as_str() {
        "serial" => serial_msm_window_bits(points),
        "parallel" => parallel_window_bits(points),
        value => value.parse()?,
    };
    let accumulator = accumulator(&args[4])?;
    let scalars = scalars(args.get(5))?;
    let fixture = MsmFixture::new(log_size, scalars, group == Group::G2);
    let phases = match group {
        Group::G1 => fixture.profile_g1(accumulator, width),
        Group::G2 => fixture.profile_g2(accumulator, width),
    };
    let ms = |duration: std::time::Duration| duration.as_secs_f64() * 1_000.0;
    let total = ms(phases.recoding)
        + ms(phases.accumulation)
        + ms(phases.reduction)
        + ms(phases.combination);
    println!(
        "group={} log_size={log_size} width={width} accumulator={}",
        args[1], args[4]
    );
    for (name, value) in [
        ("recoding", phases.recoding),
        ("accumulation", phases.accumulation),
        ("bucket_reduction", phases.reduction),
        ("window_combination", phases.combination),
    ] {
        println!(
            "{name}_ms={:.3} ({:.1}%)",
            ms(value),
            ms(value) / total * 100.0
        );
    }
    println!("total_ms={total:.3}");
    Ok(())
}

/// Nanoseconds per base-field multiplication, inversion, and XYZZ mixed
/// addition: the costs that set the batch-affine break-even batch size.
fn primitives() {
    use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
    use ark_ff::Field;

    fn time(name: &str, iterations: u32, mut operation: impl FnMut()) {
        let mut samples = (0..7)
            .map(|_| {
                let started = Instant::now();
                for _ in 0..iterations {
                    operation();
                }
                started.elapsed().as_secs_f64() * 1e9 / f64::from(iterations)
            })
            .collect::<Vec<_>>();
        println!("{name}_ns={:.1}", median(&mut samples));
    }

    let mut fq = Fq::from(0x1234_5678_u64);
    let step = Fq::from(0x9e37_79b9_u64);
    time("fq_mul", 1_000_000, || fq = black_box(fq * step));
    time("fq_inverse", 20_000, || {
        fq = black_box(fq.inverse().expect("non-zero") + step)
    });
    let mut fq2 = Fq2::new(fq, step);
    let step2 = Fq2::new(step, fq);
    time("fq2_mul", 1_000_000, || fq2 = black_box(fq2 * step2));
    time("fq2_inverse", 20_000, || {
        fq2 = black_box(fq2.inverse().expect("non-zero") + step2)
    });
    let g1 = (G1Affine::generator() * Fr::from(7_u64)).into_affine();
    let mut bucket = G1Projective::ZERO_BUCKET;
    bucket += &G1Affine::generator();
    time("g1_xyzz_mixed_add", 1_000_000, || bucket += black_box(&g1));
    let g2 = (G2Affine::generator() * Fr::from(7_u64)).into_affine();
    let mut bucket = G2Projective::ZERO_BUCKET;
    bucket += &G2Affine::generator();
    time("g2_xyzz_mixed_add", 300_000, || bucket += black_box(&g2));
    let _ = black_box((fq, fq2, bucket));
}
