#![no_main]
use std::sync::LazyLock;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
static GRAPH: LazyLock<curvy_witness::WitnessGraph> = LazyLock::new(|| {
    let bytes = include_bytes!("../corpus/graph/multiplier");
    let pin = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
    curvy_witness::WitnessGraph::from_bytes(bytes,&pin).unwrap()
});
fuzz_target!(|data: &[u8]| {
    if data.len() <= 65536 {
        if let Ok(json) = std::str::from_utf8(data) { let _ = GRAPH.calculate_json(json); }
    }
});
