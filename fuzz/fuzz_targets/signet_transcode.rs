#![no_main]
//! `curvy_signet::transcode` against the evaluator's decoder, on mutated artifacts.
//!
//! The transcoder parses bodies with its own reader. It must never refuse a raw
//! artifact the decoder accepts, must transcode whatever it accepts back to the
//! same bytes, and its output must be accepted exactly when the source is and
//! then evaluate to the same assignment.
use curvy_signet::{FormatVersion, transcode};
use curvy_witness::{Limits, WitnessGraph};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

const INPUT: &str = r#"{"a":"3","b":"11"}"#;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Small counts, but room for a body that grows from version 2 to version 1, so
/// the source and the output are never refused for their sizes alone.
fn limits() -> Limits {
    let mut limits = Limits::client();
    limits.graph_bytes = 8 * 32768;
    limits.compressed_graph_bytes = 32768;
    limits.zstd_window_bytes = 32768;
    limits.nodes = 512;
    limits.signals = 512;
    limits.input_mappings = 32;
    limits.input_values = 512;
    limits
}

fn load(bytes: &[u8]) -> Result<WitnessGraph, String> {
    WitnessGraph::from_bytes_with_limits(bytes, &hex(&Sha256::digest(bytes)), limits())
        .map_err(|e| e.to_string())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 32768 {
        return;
    }
    let source = load(data);
    let raw = data.starts_with(b"SIGNET01") || data.starts_with(b"CVYWIT01");
    let source_version = match data.get(8..10).map(|v| u16::from_le_bytes([v[0], v[1]])) {
        Some(1) => FormatVersion::V1,
        Some(2) => FormatVersion::V2,
        _ => {
            for target in [FormatVersion::V1, FormatVersion::V2] {
                assert!(
                    transcode(data, target).is_err(),
                    "transcoded an unknown body version"
                );
            }
            return;
        }
    };

    for target in [FormatVersion::V1, FormatVersion::V2] {
        let output = match transcode(data, target) {
            Ok(output) => output,
            Err(error) => {
                // A compressed artifact is the decoder's to read; transcode takes raw bodies.
                assert!(
                    !raw || source.is_err(),
                    "transcode refused an artifact the decoder accepts: {error}"
                );
                continue;
            }
        };
        assert_eq!(
            transcode(&output, source_version).expect("the output transcodes back"),
            data,
            "transcoding there and back changed the artifact"
        );
        match (&source, load(&output)) {
            (Ok(source), Ok(output)) => assert_eq!(
                output.calculate_json(INPUT).map_err(|e| e.to_string()),
                source.calculate_json(INPUT).map_err(|e| e.to_string()),
                "the transcoded artifact evaluates differently"
            ),
            (Err(_), Err(_)) => {}
            (source, output) => panic!(
                "acceptance changed in transcoding: source {:?}, output {:?}",
                source.as_ref().map(|_| ()),
                output.map(|_| ())
            ),
        }
    }
});
