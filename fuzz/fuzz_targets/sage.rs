#![no_main]
use curvy_witness::{Limits, sage::SageGraph};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
fuzz_target!(|data: &[u8]| {
    if data.len() > 32768 { return; }
    let mut limits = Limits::client();
    limits.sage_program_bytes = 32768;
    limits.nodes = 256;
    limits.signals = 256;
    limits.input_mappings = 32;
    limits.input_values = 256;
    let pin = Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect::<String>();
    // The serialized program carries the source pin at bytes 16..48.
    let source = data.get(16..48).map(|v| v.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap_or_else(|| "00".repeat(32));
    if let Ok(graph) = SageGraph::from_compiled_bytes_with_limits(data, &pin, &source, limits) {
        let _ = graph.calculate_json(r#"{"a":"3","b":"11"}"#);
    }
});
