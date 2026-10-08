//! Adversarial long-decimal input benchmark through the real graph JSON boundary.
use curvy_witness::WitnessGraph;
use sha2::{Digest, Sha256};
use std::{hint::black_box, time::Instant};
fn main() {
    let bytes = include_bytes!("../../../../fuzz/corpus/graph/multiplier");
    let pin = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let graph = WitnessGraph::from_bytes(bytes, &pin).unwrap();
    for mib in [1usize, 2, 4, 8, 15] {
        let input = format!(
            "{{\"a\":\"{}\",\"b\":\"11\"}}",
            "9".repeat(mib * 1024 * 1024)
        );
        let mut samples = Vec::new();
        for _ in 0..5 {
            let start = Instant::now();
            black_box(graph.calculate_json(&input).unwrap());
            samples.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        println!(
            "{}",
            serde_json::json!({"decimalBytes":mib*1024*1024,"jsonBytes":input.len(),"milliseconds":samples})
        );
    }
}
