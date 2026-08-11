//! Measure the same arithmetic kernels exposed by the browser benchmark.

use std::{env, time::Instant};

use curvy_prover::sparrow::phase_bench;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let threads = env::args().nth(1).map_or(Ok(8), |value| value.parse())?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    println!("runtime=native");
    println!("threads={threads}");
    measure("sha256_64m_ms", || phase_bench::sha256(8 << 20, 8))?;
    measure("fr_arithmetic_500k_ms", || {
        phase_bench::field_multiplication(500_000)
    })?;
    measure("fft_2p18_roundtrip_ms", || phase_bench::fft(18, 1))?;
    measure("g1_msm_2p17_ms", || phase_bench::g1_msm(17, 13))?;
    measure("g2_msm_2p16_ms", || phase_bench::g2_msm(16, 13))?;
    Ok(())
}

fn measure(
    name: &str,
    mut operation: impl FnMut() -> Result<u32, &'static str>,
) -> Result<(), &'static str> {
    let mut samples = Vec::with_capacity(3);
    let mut fingerprint = None;
    for _ in 0..3 {
        let started = Instant::now();
        let current = operation()?;
        if fingerprint
            .replace(current)
            .is_some_and(|old| old != current)
        {
            return Err("phase benchmark fingerprint changed between samples");
        }
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    samples.sort_by(f64::total_cmp);
    let fingerprint = fingerprint.expect("three benchmark samples");
    println!("{name}={:.3}", samples[1]);
    println!("{name}_samples={samples:.3?}");
    println!("{name}_fingerprint={fingerprint}");
    Ok(())
}
