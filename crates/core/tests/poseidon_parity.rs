//! Conformance: Poseidon must reproduce the circomlib / `poseidon-lite` reference
//! exactly for every committed test vector (all arities 1..=16, including zeros,
//! sequential, random, and near-field-max inputs).

use curvy_core::field::fr_from_dec;
use curvy_core::poseidon::poseidon;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    arity: usize,
    inputs: Vec<String>,
    output: String,
}

const VECTORS_JSON: &str = include_str!("../testdata/poseidon_vectors.json");

#[test]
fn poseidon_matches_poseidon_lite() {
    let vectors: Vec<Vector> =
        serde_json::from_str(VECTORS_JSON).expect("poseidon_vectors.json must parse");
    assert!(!vectors.is_empty(), "no test vectors loaded");

    // Sanity: every arity 1..=16 must be exercised.
    let mut seen = [false; 17];

    for (i, v) in vectors.iter().enumerate() {
        assert_eq!(v.inputs.len(), v.arity, "vector {i}: arity/inputs mismatch");
        seen[v.arity] = true;

        let inputs: Vec<_> = v.inputs.iter().map(|s| fr_from_dec(s)).collect();
        let got = poseidon(&inputs);
        let want = fr_from_dec(&v.output);

        assert_eq!(
            got, want,
            "vector {i} (arity {}) mismatch\n  inputs: {:?}\n  expected: {}",
            v.arity, v.inputs, v.output
        );
    }

    for (arity, &hit) in seen.iter().enumerate().skip(1) {
        assert!(hit, "no test vector for arity {arity}");
    }
}

/// Second, independent reference: Light Protocol's `light-poseidon` (audited by
/// Veridise, circom-compatible parameters). The committed vectors above pin the
/// implementation to circomlib/`poseidon-lite`; this cross-checks the same
/// permutation against a separately-implemented, audited Rust codebase. It
/// supports arities 1..=12 - 13..=16 remain covered by the committed vectors only.
#[test]
fn poseidon_matches_light_poseidon() {
    use curvy_core::field::Fr;
    use light_poseidon::{Poseidon, PoseidonHasher};

    // Deterministic full-width inputs: a Poseidon hash chain, so every input is a
    // high-entropy field element rather than a small integer.
    let mut x = poseidon(&[fr_from_dec("424242424242424242424242424242")]);
    for arity in 1..=12usize {
        let inputs: Vec<Fr> = (0..arity)
            .map(|_| {
                x = poseidon(&[x]);
                x
            })
            .collect();
        let ours = poseidon(&inputs);
        let theirs = Poseidon::<Fr>::new_circom(arity)
            .expect("light-poseidon supports arity 1..=12")
            .hash(&inputs)
            .expect("light-poseidon hash");
        assert_eq!(ours, theirs, "arity {arity}: hand-rolled Poseidon != light-poseidon");
    }
}
