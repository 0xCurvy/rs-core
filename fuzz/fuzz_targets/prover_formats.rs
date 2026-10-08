#![no_main]
use std::io::Cursor;
use std::sync::LazyLock;
use curvy_prover::artifacts::manifest::ZkeyChunkManifest;
use curvy_prover::sparrow::{self, StreamingConfig};
use curvy_witness::WitnessGraph;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
// Supplies a multiplier-shaped witness, so mutated keys of the same shape get past
// the assignment checks and into proving.
static GRAPH: LazyLock<WitnessGraph> = LazyLock::new(|| {
    let bytes = include_bytes!("../corpus/graph/multiplier");
    WitnessGraph::from_bytes(bytes, &hex(&Sha256::digest(bytes))).unwrap()
});
// Small windows, chunks and I/O reads put every boundary inside a tiny key.
const STREAMING: StreamingConfig =
    StreamingConfig { window_bits: 4, msm_chunk_points: 3, io_chunk_bytes: 97 };
/// Manifest the (mutated) key itself, so its bytes reach the manifest-authenticated
/// parsers rather than stopping at a chunk-hash mismatch.
fn manifest_for(zkey: &[u8]) -> Option<ZkeyChunkManifest> {
    let (encoded, pin) = ZkeyChunkManifest::generate(&mut Cursor::new(zkey), 64 * 1024).ok()?;
    let manifest = ZkeyChunkManifest::from_bytes(&encoded, &pin, &hex(&encoded[24..56]))
        .expect("a generated manifest parses");
    assert_eq!(manifest.zkey_sha256(), hex(&Sha256::digest(zkey)));
    Some(manifest)
}
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 { return; }
    let Some((&format, data)) = data.split_first() else { return; };
    match format % 5 {
        0 => { let _ = curvy_prover::wtns::read_wtns(data); }
        1 => { let _ = curvy_prover::zkey::read_zkey(&mut std::io::Cursor::new(data)); }
        2 => {
            let pin = Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect::<String>();
            let key_pin = data.get(24..56).map(|v| v.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap_or_else(|| "00".repeat(32));
            if let Ok(manifest) = curvy_prover::artifacts::manifest::ZkeyChunkManifest::from_bytes(data, &pin, &key_pin) {
                let mut key = &include_bytes!("../../crates/prover/testdata/multiplier.zkey")[..];
                let _ = curvy_prover::Prover::from_zkey_manifest_reader(&mut key, &manifest);
            }
        }
        // Resident one-pass parsers over the mutated key.
        3 => {
            if let Ok((_, _, digest)) = curvy_prover::zkey::read_zkey_sequential(&mut Cursor::new(data)) {
                // The returned digest is the caller's only authentication hook.
                assert_eq!(digest[..], Sha256::digest(data)[..], "digest must cover every byte");
            }
            // With `zkey-single-pass`, the whole-file pin gates the same forward walk.
            let _ = curvy_prover::Prover::from_zkey_reader(&mut Cursor::new(data), &hex(&Sha256::digest(data)));
            if let Some(manifest) = manifest_for(data) {
                let _ = curvy_prover::Prover::from_zkey_manifest_reader(&mut Cursor::new(data), &manifest);
            }
        }
        // SPARROW streaming proofs over the mutated key, seekable and manifest-fed.
        _ => {
            let assignment = GRAPH.calculate_json(r#"{"a":"3","b":"11"}"#).unwrap();
            let pin = hex(&Sha256::digest(data));
            let _ = sparrow::prove_reader(&mut Cursor::new(data), &assignment, &pin, STREAMING);
            if let Some(manifest) = manifest_for(data) {
                let _ = sparrow::manifest::prove_reader_with_manifest_owned(
                    &mut Cursor::new(data),
                    assignment,
                    manifest,
                    STREAMING,
                );
            }
        }
    }
});
