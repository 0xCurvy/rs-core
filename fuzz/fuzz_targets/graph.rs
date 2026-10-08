#![no_main]
use std::sync::{LazyLock, Mutex, PoisonError};
use curvy_witness::{Limits, WitnessGraph, WitnessWorkspace, sage::SageGraph};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
const INPUT: &str = r#"{"a":"3","b":"11"}"#;
// Small enough that larger graphs exceed it, so both the retained and the
// released branches of the workspace run.
const RETAINED_BYTES: usize = 4096;
// Reused across iterations, so stale buffer contents would surface as a mismatch.
static WORKSPACE: LazyLock<Mutex<WitnessWorkspace>> =
    LazyLock::new(|| Mutex::new(WitnessWorkspace::new(RETAINED_BYTES)));
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
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
    let pin = hex(&Sha256::digest(data));
    let graph = WitnessGraph::from_bytes_with_limits(data, &pin, limits);
    let sage = SageGraph::from_bytes_with_limits(data, &pin, limits);
    // SAGE shares the authenticated decoder, so it accepts exactly the same artifacts.
    assert_eq!(graph.is_ok(), sage.is_ok(), "evaluators disagree on acceptance");
    let (Ok(graph), Ok(sage)) = (graph, sage) else { return };
    let expected = graph.calculate_json(INPUT).map_err(|e| e.to_string());
    assert_eq!(sage.calculate_json(INPUT).map_err(|e| e.to_string()), expected);

    let mut workspace = WORKSPACE.lock().unwrap_or_else(PoisonError::into_inner);
    let reused = graph.with_witness_json(INPUT, &mut workspace, |a| a.to_vec());
    assert_eq!(reused.map_err(|e| e.to_string()), expected);
    assert!(workspace.retained_bytes() <= RETAINED_BYTES);
    let reused = sage.with_witness_json(INPUT, &mut workspace, |a| a.to_vec());
    assert_eq!(reused.map_err(|e| e.to_string()), expected);
    assert!(workspace.retained_bytes() <= RETAINED_BYTES);

    // The compiled-program cache round-trips for every graph SAGE accepts.
    let program = sage.to_compiled_bytes().expect("compiled program encodes");
    let cached =
        SageGraph::from_compiled_bytes_with_limits(&program, &hex(&Sha256::digest(&program)), &pin, limits)
            .expect("compiled program decodes");
    assert_eq!(cached.calculate_json(INPUT).map_err(|e| e.to_string()), expected);
});
