//! A graph from curvy-signet-ir-builder, checked offline against circom's witness.
//!
//! `tests/fixtures/ir-builder-smoke` holds the graph the builder wrote for
//! `smoke.circom` (the circuit `scripts/smoke-graph.sh` builds), three inputs that
//! take both sides of each of its input-dependent selects, and the witness circom
//! 2.2.3 computed for each. The smoke script needs circom, node and the builder; this
//! test needs none of them, so a change to the postcard schema `--ops patched`
//! decodes, to the exporter or to the evaluator is caught by `cargo test` alone.

use std::path::{Path, PathBuf};

use curvy_signet::{Envelope, FormatVersion, Graph, OperationSchema, encode, hex, wtns};
use curvy_witness::WitnessGraph;
use sha2::{Digest, Sha256};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ir-builder-smoke")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

#[test]
fn the_builders_graph_computes_circoms_witness() {
    let graph = Graph::from_postcard(&read("graph.bin"), OperationSchema::Patched)
        .expect("the builder writes the patched schema");
    for version in [FormatVersion::V1, FormatVersion::V2] {
        let artifact = encode(&graph, [0; 32], Envelope::Signet, version).expect("encode");
        let digest = hex(&Sha256::digest(&artifact));
        let evaluator = WitnessGraph::from_bytes(&artifact, &digest)
            .expect("the evaluator accepts the exported artifact");
        for case in 1..=3 {
            let input = String::from_utf8(read(&format!("input-{case}.json"))).unwrap();
            let expected = wtns::read(&read(&format!("witness-{case}.wtns"))).expect("wtns");
            let witness = evaluator.calculate_json(&input).expect("evaluate");
            assert_eq!(
                wtns::first_difference(&witness, &expected),
                None,
                "{version:?}, input {input}"
            );
        }
    }
}
