use std::{hint::black_box, time::Instant};

use ark_bn254::Fr;
use ark_ff::PrimeField;

fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "packed".to_owned());
    let log_size = argument(2, 18_u32);
    let rounds = argument(3, 5_usize);
    let size = 1usize
        .checked_shl(log_size)
        .expect("benchmark log size must fit usize");
    let assignment = deterministic_scalars(size);

    for sample in 1..=rounds {
        let started = Instant::now();
        let bytes = match mode.as_str() {
            "json" => curvy_prover::publics_to_json(&assignment).into_bytes(),
            "packed" => curvy_prover::assignment_to_packed_be(&assignment),
            _ => panic!("mode must be json or packed"),
        };
        let elapsed = started.elapsed();
        black_box(&bytes);
        println!(
            "mode={mode} fields={size} sample={sample} output_bytes={} elapsed_ms={:.3}",
            bytes.len(),
            elapsed.as_secs_f64() * 1_000.0,
        );
    }
}

fn deterministic_scalars(size: usize) -> Vec<Fr> {
    let mut state = 0x7769_746e_6573_7331_u64;
    (0..size)
        .map(|_| {
            let mut bytes = [0_u8; 32];
            for word in bytes.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                word.copy_from_slice(&state.to_le_bytes());
            }
            Fr::from_le_bytes_mod_order(&bytes)
        })
        .collect()
}

fn argument<T: std::str::FromStr>(index: usize, default: T) -> T {
    std::env::args()
        .nth(index)
        .map(|value| value.parse().ok().expect("valid benchmark argument"))
        .unwrap_or(default)
}
