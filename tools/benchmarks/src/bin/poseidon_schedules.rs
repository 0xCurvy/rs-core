//! Release-mode A/B harness for the direct and optimized Poseidon schedules.
//! Build once normally and once with `--features poseidon-optimized`.

use std::{env, hint::black_box, time::Instant};

use ark_bn254::Fr;
use curvy_core::poseidon::poseidon;

fn main() {
    let cold_only = env::args().nth(1).as_deref() == Some("--cold-only");
    let iterations = if cold_only { 1 } else { argument(1, 10_000) };
    let samples = if cold_only { 1 } else { argument(2, 7) };
    assert!(iterations != 0 && samples != 0);
    let cold_started = Instant::now();
    let cold_digest = poseidon(black_box(&[Fr::from(1), Fr::from(2)]));
    let cold_init_us = cold_started.elapsed().as_secs_f64() * 1_000_000.0;
    println!(
        "schedule={}, iterations={}, samples={}, cold_init_us={cold_init_us:.1}, cold_digest={cold_digest:?}",
        if cfg!(feature = "poseidon-optimized") {
            "optimized"
        } else {
            "reference"
        },
        iterations,
        samples,
    );
    if cold_only {
        return;
    }
    println!("arity,min_ns,median_ns,max_ns,mean_ns,stdev_ns,digest");

    for arity in 1..=16 {
        let mut times = Vec::with_capacity(samples);
        let mut digest = Fr::from(arity as u64);
        for sample in 0..samples {
            let mut inputs = (0..arity)
                .map(|index| Fr::from((index + sample + 1) as u64))
                .collect::<Vec<_>>();
            for _ in 0..32 {
                digest = poseidon(black_box(&inputs));
                inputs[0] = digest;
            }
            let start = Instant::now();
            for iteration in 0..iterations {
                inputs[iteration % arity] += digest;
                digest = poseidon(black_box(&inputs));
            }
            times.push(start.elapsed().as_nanos() as f64 / iterations as f64);
        }
        times.sort_by(f64::total_cmp);
        let mean = times.iter().sum::<f64>() / samples as f64;
        let stdev = if samples == 1 {
            0.0
        } else {
            (times
                .iter()
                .map(|sample| (sample - mean).powi(2))
                .sum::<f64>()
                / (samples - 1) as f64)
                .sqrt()
        };
        println!(
            "{arity},{:.1},{:.1},{:.1},{mean:.1},{stdev:.1},{digest:?}",
            times[0],
            times[times.len() / 2],
            times[times.len() - 1],
        );
    }
}

fn argument(position: usize, default: usize) -> usize {
    env::args()
        .nth(position)
        .map(|value| value.parse().expect("arguments must be positive integers"))
        .unwrap_or(default)
}
