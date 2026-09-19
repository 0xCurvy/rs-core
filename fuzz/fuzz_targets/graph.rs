#![no_main]
use curvy_witness::{Limits, WitnessGraph};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
fuzz_target!(|data: &[u8]| {
    if data.len() > 32768 { return; }
    let mut limits = Limits::client();
    limits.graph_bytes = 32768;
    limits.compressed_graph_bytes = 32768;
    limits.zstd_window_bytes = 32768;
    limits.nodes = 256;
    limits.signals = 256;
    limits.input_mappings = 32;
    limits.input_values = 256;
    // Recompute the pin so mutations exercise the authenticated parser body.
    let pin = Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect::<String>();
    if let Ok(graph) = WitnessGraph::from_bytes_with_limits(data, &pin, limits) {
        let _ = graph.calculate_json(r#"{"a":"3","b":"11"}"#);
    }
});
