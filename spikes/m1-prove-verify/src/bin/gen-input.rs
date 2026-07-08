//! Generate the withdrawal(2,30) circuit input fixture from rs-core's committed
//! witness-parity vectors (crates/core/testdata/witness_vectors.json).
//!
//! The committed vector's inclusion proofs are depth-6 (parity-test scale); the
//! deployed circuit is treeDepth=30, so we rebuild the tree at depth 30 from the
//! same two notes with `curvy_core::imt` and re-derive proofs/root/signature via
//! `witness::build_withdrawal`. Everything else (key, notes, destination, token)
//! is taken verbatim from the committed vector.
//!
//! Outputs (under fixtures/):
//!   - input.json            flat snarkjs input object for the (2,30) circuit
//!   - expected-public.json  the 6 public signals in on-chain order:
//!                           [withdrawnAmount, nullifiers[0], nullifiers[1],
//!                            notesRoot, destinationAddress, tokenId]

use curvy_core::field::{fr_from_dec, fr_to_dec, Fr};
use curvy_core::imt::Imt;
use curvy_core::witness::{build_withdrawal, Note, Proof};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../crates/core/testdata/witness_vectors.json");
const TREE_DEPTH: usize = 30;

fn fr(v: &Value) -> Fr {
    fr_from_dec(v.as_str().expect("expected decimal string"))
}

fn note_of(v: &Value) -> Note {
    Note {
        amount: fr(&v["amount"]),
        token: fr(&v["token"]),
        owner_pub: (fr(&v["ownerPub"][0]), fr(&v["ownerPub"][1])),
        shared_secret: fr(&v["sharedSecret"]),
        ephemeral_key: (fr(&v["ephemeralKey"][0]), fr(&v["ephemeralKey"][1])),
        view_tag: fr(&v["viewTag"]),
    }
}

fn main() -> anyhow::Result<()> {
    let root: Value = serde_json::from_str(VECTORS)?;
    let w = &root["withdrawal"];

    let notes: Vec<Note> = w["notes"].as_array().unwrap().iter().map(note_of).collect();
    let key = w["key"].as_str().unwrap();
    let public_key = (fr(&w["publicKey"][0]), fr(&w["publicKey"][1]));
    let destination = fr(&w["destinationAddress"]);
    let token = fr(&w["tokenId"]);

    // Depth-30 IMT over the two note ids (leaf order = note order).
    let ids: Vec<Fr> = notes.iter().map(|n| n.id()).collect();
    let tree = Imt::from_leaves(TREE_DEPTH, &ids);
    let proofs: Vec<Proof> = (0..notes.len())
        .map(|i| {
            let p = tree.create_proof(i);
            assert!(curvy_core::imt::verify_proof(&p), "imt proof {i} must verify");
            Proof { leaf_index: i as u64, siblings: p.siblings }
        })
        .collect();
    let notes_root = tree.root();

    let input = build_withdrawal(&notes, key, public_key, &proofs, notes_root, destination, token);

    // Expected public signals, in the order snarkjs/the verifier see them:
    // outputs first (declaration order: withdrawnAmount, nullifiers[2]), then
    // public inputs (declaration order: notesRoot, destinationAddress, tokenId).
    use ark_ff::AdditiveGroup;
    let total: Fr = notes.iter().fold(Fr::ZERO, |a, n| a + n.amount);
    let expected_public: Vec<String> = vec![
        fr_to_dec(&total),
        fr_to_dec(&notes[0].nullifier()),
        fr_to_dec(&notes[1].nullifier()),
        fr_to_dec(&notes_root),
        fr_to_dec(&destination),
        fr_to_dec(&token),
    ];

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("input.json"), serde_json::to_string_pretty(&input)?)?;
    std::fs::write(dir.join("expected-public.json"), serde_json::to_string_pretty(&expected_public)?)?;
    println!("wrote fixtures/input.json and fixtures/expected-public.json");
    println!("notesRoot (depth-30): {}", fr_to_dec(&notes_root));
    Ok(())
}
