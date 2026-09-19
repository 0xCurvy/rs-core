use std::{hint::black_box, time::Instant};

use curvy_prover::proof_bench::ProofMsmFixture;
use rayon::ThreadPoolBuilder;

fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sequential".to_owned());
    let log_size = argument(2, 16_u32);
    let threads = argument(3, 4_usize);
    let chunk_points = argument(4, 16_384_usize);

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("benchmark Rayon pool");
    let fixture = ProofMsmFixture::new(log_size);
    let started = Instant::now();
    let output = pool.install(|| match mode.as_str() {
        "sequential" => fixture.materialized_sequential(),
        "concurrent" => fixture.materialized_concurrent(),
        "chunked" => fixture.chunked_sequential(chunk_points),
        _ => panic!("mode must be sequential, concurrent, or chunked"),
    });
    black_box(output);
    println!(
        "mode={mode} points={} threads={threads} chunk_points={chunk_points} elapsed_ms={:.3}",
        fixture.points(),
        started.elapsed().as_secs_f64() * 1_000.0,
    );
}

fn argument<T: std::str::FromStr>(index: usize, default: T) -> T {
    std::env::args()
        .nth(index)
        .map(|value| value.parse().ok().expect("valid benchmark argument"))
        .unwrap_or(default)
}
