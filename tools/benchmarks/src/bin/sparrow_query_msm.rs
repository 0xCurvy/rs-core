//! Time SPARROW's streamed query MSM (bucket accumulation across chunks plus
//! the final reduction) on a deterministic zkey-encoded query section.
//!
//! Builds with or without the `parallel` feature, so the same command measures
//! the native Rayon path and the serial (single-threaded WASM-shaped) path:
//!
//! ```text
//! cargo run --release -p curvy-benchmarks --bin sparrow_query_msm -- g1 18 13 0 524288
//! cargo run --release -p curvy-benchmarks --no-default-features --bin sparrow_query_msm -- g1 18 1 13 65536
//! ```
//!
//! The printed `result` is the affine MSM value, for comparing builds.

use std::{env, hint::black_box, sync::Arc, time::Instant};

use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use curvy_prover::{
    StreamingConfig,
    sparrow::{bench_query_msm_g1, bench_query_msm_g2},
};

const USAGE: &str = "usage: sparrow_query_msm <g1|g2> <log-size> <threads> <window-bits|0=adaptive> <msm-chunk-points> [samples=7] [uniform|witness|ones]";
/// Bytes handed to the accumulator per push, like the 1 MiB I/O chunks.
const PUSH_BYTES: usize = 1 << 20;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if !(5..=7).contains(&args.len()) {
        return Err(USAGE.into());
    }
    let g2 = match args[0].as_str() {
        "g1" => false,
        "g2" => true,
        _ => return Err(USAGE.into()),
    };
    let log_size = args[1].parse::<u32>()?;
    let threads = args[2].parse::<usize>()?;
    let config = StreamingConfig {
        window_bits: args[3].parse()?,
        msm_chunk_points: args[4].parse()?,
        ..StreamingConfig::default()
    };
    let samples = args.get(5).map_or(Ok(7), |value| value.parse::<usize>())?;
    if samples == 0 || threads == 0 {
        return Err("samples and threads must be positive".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;

    let size = 1_usize << log_size;
    let scalars: Arc<[Fr]> = scalars(size, args.get(6).map_or("uniform", String::as_str))?.into();
    let section = if g2 { encode_g2(size) } else { encode_g1(size) };

    let run = || -> Result<(f64, String), Box<dyn std::error::Error>> {
        let started = Instant::now();
        let result = if g2 {
            let value = bench_query_msm_g2(&section, Arc::clone(&scalars), config, PUSH_BYTES)?;
            black_box(value).into_affine().to_string()
        } else {
            let value = bench_query_msm_g1(&section, Arc::clone(&scalars), config, PUSH_BYTES)?;
            black_box(value).into_affine().to_string()
        };
        Ok((started.elapsed().as_secs_f64() * 1_000.0, result))
    };
    let (_, reference) = run()?;
    let mut timings = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (elapsed, result) = run()?;
        if result != reference {
            return Err("result changed between samples".into());
        }
        timings.push(elapsed);
    }
    let mut sorted = timings.clone();
    sorted.sort_by(f64::total_cmp);
    println!(
        "group={} log_size={log_size} threads={threads} window_bits={} msm_chunk_points={} parallel={} median_ms={:.3} min_ms={:.3} max_ms={:.3}",
        args[0],
        config.window_bits,
        config.msm_chunk_points,
        cfg!(feature = "parallel"),
        sorted[sorted.len() / 2],
        sorted[0],
        sorted[sorted.len() - 1],
    );
    println!("samples_ms={timings:.3?}");
    println!("result={reference}");
    Ok(())
}

fn scalars(size: usize, kind: &str) -> Result<Vec<Fr>, Box<dyn std::error::Error>> {
    let mut state = 0x7370_6172_726f_7731_u64;
    let uniform = (0..size).map(|_| {
        let mut bytes = [0_u8; 32];
        for word in bytes.chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            word.copy_from_slice(&state.to_le_bytes());
        }
        Fr::from_le_bytes_mod_order(&bytes)
    });
    Ok(match kind {
        "uniform" => uniform.collect(),
        "ones" => vec![Fr::from(1_u64); size],
        "witness" => uniform
            .enumerate()
            .map(|(index, scalar)| match index % 4 {
                0 => Fr::from(0_u64),
                1 => Fr::from(1_u64),
                2 => Fr::from(scalar.into_bigint().0[0]),
                _ => scalar,
            })
            .collect(),
        _ => return Err("scalars must be uniform, witness, or ones".into()),
    })
}

/// `(1 + i) * G` for `i in 0..size`, as Montgomery-form zkey bytes.
fn encode_g1(size: usize) -> Vec<u8> {
    let generator = G1Projective::generator();
    let mut point = generator;
    let mut points = Vec::with_capacity(size);
    for _ in 0..size {
        points.push(point);
        point += generator;
    }
    let mut bytes = Vec::with_capacity(size * 64);
    for point in G1Projective::normalize_batch(&points) {
        for limb in point.x.0.0.iter().chain(&point.y.0.0) {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    bytes
}

fn encode_g2(size: usize) -> Vec<u8> {
    let generator = G2Projective::generator();
    let mut point = generator;
    let mut points = Vec::with_capacity(size);
    for _ in 0..size {
        points.push(point);
        point += generator;
    }
    let mut bytes = Vec::with_capacity(size * 128);
    for point in G2Projective::normalize_batch(&points) {
        for coordinate in [point.x.c0, point.x.c1, point.y.c0, point.y.c1] {
            for limb in coordinate.0.0 {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
        }
    }
    bytes
}
