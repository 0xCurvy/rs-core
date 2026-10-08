//! Compare dense arkworks rows with Curvy's CSR evaluator. This binary needs
//! `--features compact-matrix` because the prototype is deliberately opt-in.

#[cfg(feature = "compact-matrix")]
use std::{env, hint::black_box, time::Instant};

#[cfg(feature = "compact-matrix")]
use curvy_prover::proof_bench::MatrixEvaluationFixture;

#[cfg(feature = "compact-matrix")]
fn main() {
    let rows = argument(1, 1 << 20);
    let stride = argument(2, 5);
    let samples = argument(3, 7);
    let workers = argument(4, 4);
    rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build_global()
        .expect("global benchmark pool must initialize");
    let fixture = MatrixEvaluationFixture::new(rows, stride);
    let expected = fixture.dense_evaluations();
    assert_eq!(fixture.compact_evaluations(), expected);

    let mut dense_ms = Vec::with_capacity(samples);
    let mut compact_ms = Vec::with_capacity(samples);
    for sample in 0..samples {
        if sample % 2 == 0 {
            dense_ms.push(measure(|| fixture.dense_evaluations()));
            compact_ms.push(measure(|| fixture.compact_evaluations()));
        } else {
            compact_ms.push(measure(|| fixture.compact_evaluations()));
            dense_ms.push(measure(|| fixture.dense_evaluations()));
        }
    }
    dense_ms.sort_by(f64::total_cmp);
    compact_ms.sort_by(f64::total_cmp);
    println!("rows={rows}");
    println!("nonzero_stride={stride}");
    println!("workers={}", rayon::current_num_threads());
    println!("dense_storage_bytes={}", fixture.dense_storage_bytes());
    println!("compact_storage_bytes={}", fixture.compact_storage_bytes());
    println!("dense_evaluation_median_ms={:.3}", dense_ms[samples / 2]);
    println!(
        "compact_evaluation_median_ms={:.3}",
        compact_ms[samples / 2]
    );
}

#[cfg(feature = "compact-matrix")]
fn measure(run: impl FnOnce() -> Vec<ark_bn254::Fr>) -> f64 {
    let started = Instant::now();
    black_box(run());
    started.elapsed().as_secs_f64() * 1_000.0
}

#[cfg(feature = "compact-matrix")]
fn argument(position: usize, default: usize) -> usize {
    env::args()
        .nth(position)
        .map(|value| value.parse().expect("arguments must be positive integers"))
        .unwrap_or(default)
}

#[cfg(not(feature = "compact-matrix"))]
fn main() {
    eprintln!("rerun with --features compact-matrix");
}
