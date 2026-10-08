#![no_main]
use curvy_witness::{Limits, WitnessError, sage::SageGraph};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
const INPUT: &str = r#"{"a":"3","b":"11"}"#;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fuzz_target!(|data: &[u8]| {
    if data.len() > 32768 { return; }
    let mut limits = Limits::client();
    limits.sage_program_bytes = 32768;
    limits.zstd_window_bytes = 32768;
    limits.nodes = 256;
    limits.signals = 256;
    limits.input_mappings = 32;
    limits.input_values = 256;
    let pin = hex(&Sha256::digest(data));
    // A raw program carries the source pin at bytes 16..48. A zstd frame carries
    // it at that offset of the *decompressed* stream, which the decoder reports
    // on mismatch; retry once with it so compressed inputs reach the body decoder.
    let source = data.get(16..48).map(hex).unwrap_or_else(|| "00".repeat(32));
    let graph = match SageGraph::from_compiled_bytes_with_limits(data, &pin, &source, limits) {
        Err(WitnessError::SageSourceHashMismatch { actual, .. }) => {
            SageGraph::from_compiled_bytes_with_limits(data, &pin, &actual, limits)
        }
        result => result,
    };
    if let Ok(graph) = graph {
        let assignment = graph.calculate_json(INPUT).map_err(|e| e.to_string());
        // Anything the decoder accepts must re-encode to a program it accepts
        // again and that evaluates identically.
        let bytes = graph.to_compiled_bytes().expect("decoded program re-encodes");
        // The raw encoding is canonical: the decoder rejects every variation.
        if !data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            assert_eq!(bytes, data, "accepted a non-canonical raw program");
        }
        let reloaded = SageGraph::from_compiled_bytes_with_limits(
            &bytes,
            &hex(&Sha256::digest(&bytes)),
            &hex(&graph.source_graph_sha256()),
            limits,
        )
        .expect("re-encoded program decodes");
        assert_eq!(reloaded.calculate_json(INPUT).map_err(|e| e.to_string()), assignment);
    }
});
