//! Application-level Poseidon A/B using Curvy's real indexed Merkle tree.
//! Build normally and with `--features poseidon-optimized`.

use std::{env, hint::black_box, time::Instant};

use ark_bn254::Fr;
use curvy_core::imt::IndexedMerkleTree;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let samples = env::args()
        .nth(1)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(9);
    assert!(samples != 0);

    let bulk_leaves = (1..=4_096).map(Fr::from).collect::<Vec<_>>();
    let incremental_leaves = (1..=256).map(Fr::from).collect::<Vec<_>>();

    // Warm lazy constants and allocator paths outside the measured samples.
    black_box(IndexedMerkleTree::from_leaves(16, &bulk_leaves)?.root());
    let mut warm_incremental = IndexedMerkleTree::new(30)?;
    for &leaf in &incremental_leaves {
        warm_incremental.insert(leaf)?;
    }
    black_box(warm_incremental.root());

    let mut bulk_ms = Vec::with_capacity(samples);
    let mut insert_ms = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        let tree = IndexedMerkleTree::from_leaves(16, &bulk_leaves)?;
        bulk_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        black_box(tree.root());

        let started = Instant::now();
        let mut tree = IndexedMerkleTree::new(30)?;
        for &leaf in &incremental_leaves {
            tree.insert(leaf)?;
        }
        insert_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        black_box(tree.root());
    }

    println!(
        "schedule={},samples={samples}",
        if cfg!(feature = "poseidon-optimized") {
            "optimized"
        } else {
            "reference"
        }
    );
    report("bulk_4096_depth_16_ms", &mut bulk_ms);
    report("insert_256_depth_30_ms", &mut insert_ms);
    Ok(())
}

fn report(name: &str, samples: &mut [f64]) {
    samples.sort_by(f64::total_cmp);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let stdev = if samples.len() == 1 {
        0.0
    } else {
        (samples
            .iter()
            .map(|sample| (sample - mean).powi(2))
            .sum::<f64>()
            / (samples.len() - 1) as f64)
            .sqrt()
    };
    println!(
        "{name}: min={:.3},median={:.3},max={:.3},mean={mean:.3},stdev={stdev:.3}",
        samples[0],
        samples[samples.len() / 2],
        samples[samples.len() - 1],
    );
}
