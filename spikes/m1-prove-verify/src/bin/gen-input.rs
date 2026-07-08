//! Generate the circuit input fixtures for all three deployed Curvy circuit configs
//! from rs-core's committed witness-parity vectors
//! (`crates/core/testdata/witness_vectors.json`), rebuilt at the *deployed* tree
//! dimensions (treeDepth=30). Everything else (keys, notes, amounts, tokens) is taken
//! verbatim from the committed vectors, so the inputs are real, balanced, and
//! circuit-satisfiable — not synthetic noise.
//!
//! Deployed configs (per v3-e2e Ignition Devenv, verifier registry):
//!   - withdrawal:  VerifySingleWithdrawalNoHashing(2, 30)          → uint256[6]
//!   - aggregation: VerifySingleAggregationNoHashing(2, 3, 30, 6)   → uint256[31]
//!   - pending:     VerifyPendingNotesCommitment(5, 30)             → uint256[1]
//!
//! Outputs (per circuit, under fixtures/<circuit>/ — withdrawal is flat in fixtures/):
//!   - input.json            flat snarkjs input object
//!   - expected-public.json  the public signals in on-chain (circom witness) order,
//!                           recomputed independently from rs-core primitives.

use curvy_core::field::{fr_from_dec, fr_to_dec, Fr};
use curvy_core::imt::Imt;
use curvy_core::witness::{
    build_aggregation, build_pending_commitment, build_withdrawal, Note, Proof,
};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

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

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Depth-`TREE_DEPTH` IMT over `notes` (leaf order = note order) → (proofs, root).
fn build_tree(notes: &[Note]) -> (Vec<Proof>, Fr) {
    let ids: Vec<Fr> = notes.iter().map(|n| n.id()).collect();
    let tree = Imt::from_leaves(TREE_DEPTH, &ids);
    let proofs: Vec<Proof> = (0..notes.len())
        .map(|i| {
            let p = tree.create_proof(i);
            assert!(curvy_core::imt::verify_proof(&p), "imt proof {i} must verify");
            Proof { leaf_index: i as u64, siblings: p.siblings }
        })
        .collect();
    (proofs, tree.root())
}

fn write_fixture<T: Serialize>(dir: &Path, name: &str, value: &T) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(name), serde_json::to_string_pretty(value)?)?;
    Ok(())
}

// ── withdrawal(2,30) ──────────────────────────────────────────────────────────

fn gen_withdrawal(root: &Value) -> anyhow::Result<()> {
    use ark_ff::AdditiveGroup;
    let w = &root["withdrawal"];
    let notes: Vec<Note> = w["notes"].as_array().unwrap().iter().map(note_of).collect();
    let key = w["key"].as_str().unwrap();
    let public_key = (fr(&w["publicKey"][0]), fr(&w["publicKey"][1]));
    let destination = fr(&w["destinationAddress"]);
    let token = fr(&w["tokenId"]);

    let (proofs, notes_root) = build_tree(&notes);
    let input = build_withdrawal(&notes, key, public_key, &proofs, notes_root, destination, token);

    // Public signals, on-chain order: outputs (withdrawnAmount, nullifiers[2]) then
    // public inputs (notesRoot, destinationAddress, tokenId).
    let total: Fr = notes.iter().fold(Fr::ZERO, |a, n| a + n.amount);
    let expected: Vec<String> = vec![
        fr_to_dec(&total),
        fr_to_dec(&notes[0].nullifier()),
        fr_to_dec(&notes[1].nullifier()),
        fr_to_dec(&notes_root),
        fr_to_dec(&destination),
        fr_to_dec(&token),
    ];

    let dir = fixtures_dir();
    write_fixture(&dir, "input.json", &input)?;
    write_fixture(&dir, "expected-public.json", &expected)?;
    println!("withdrawal:  fixtures/input.json (+ expected-public.json)  notesRoot={}", fr_to_dec(&notes_root));
    Ok(())
}

// ── aggregation(2,3,30,6) ─────────────────────────────────────────────────────

fn gen_aggregation(root: &Value) -> anyhow::Result<()> {
    let a = &root["aggregation"];
    let input_notes: Vec<Note> = a["inputNotes"].as_array().unwrap().iter().map(note_of).collect();
    let mut output_notes: Vec<Note> = a["outputNotes"].as_array().unwrap().iter().map(note_of).collect();
    let fee_note = note_of(&a["feeNote"]);
    let key = a["key"].as_str().unwrap();
    let public_key = (fr(&a["publicKey"][0]), fr(&a["publicKey"][1]));
    let protocol_fee = fr(&a["protocolFeePerThousand"]);
    let gas_fee = fr(&a["gasFee"]);
    let fee_note_public_key = (fr(&a["feeNotePublicKey"][0]), fr(&a["feeNotePublicKey"][1]));

    // The committed vector is a valid (2,2,·) aggregation. The deployed circuit is
    // maxOutputs=3, so pad with a zero-amount output note owned by the sender (same
    // token). A zero-amount output changes neither totalOutputValue nor the protocol
    // fee base (totalSpentValue), so value conservation is preserved; its noteId and
    // encrypted-data still enter the signed input hash exactly like a real output.
    let pad = Note {
        amount: Fr::from(0u64),
        token: input_notes[0].token,
        owner_pub: public_key,
        shared_secret: output_notes[1].shared_secret,
        ephemeral_key: output_notes[1].ephemeral_key,
        view_tag: output_notes[1].view_tag,
    };
    output_notes.push(pad);

    // Depth-30 notesRoot over the input note ids (only inputs need tree membership).
    let (input_proofs, notes_root) = build_tree(&input_notes);

    let input = build_aggregation(
        &input_notes,
        &input_proofs,
        &output_notes,
        &fee_note,
        key,
        public_key,
        notes_root,
        protocol_fee,
        gas_fee,
        fee_note_public_key,
    );

    // Public signals, on-chain (circom witness) order for
    // VerifySingleAggregationNoHashing(2,3,30,6): outputs first (nullifiers[2],
    // outputNoteIds[maxOutputs+1=4]) then public inputs in template declaration order
    // (encryptedNoteData[4]×5, notesRoot, protocolFeePerThousand,
    // commitPendingNotesGasFeeRoot, feeNotePublicKey[2]) = 31 signals total.
    let mut expected: Vec<String> = Vec::with_capacity(31);
    for n in &input_notes {
        expected.push(fr_to_dec(&n.nullifier()));
    }
    for n in &output_notes {
        expected.push(fr_to_dec(&n.id()));
    }
    expected.push(fr_to_dec(&fee_note.id()));
    for row in &input.encrypted_note_data {
        for v in row {
            expected.push(v.clone());
        }
    }
    expected.push(input.notes_root.clone());
    expected.push(input.protocol_fee_per_thousand.clone());
    expected.push(input.commit_pending_notes_gas_fee_root.clone());
    expected.push(input.fee_note_public_key[0].clone());
    expected.push(input.fee_note_public_key[1].clone());
    assert_eq!(expected.len(), 31, "aggregation must have 31 public signals");

    let dir = fixtures_dir().join("aggregation");
    write_fixture(&dir, "input.json", &input)?;
    write_fixture(&dir, "expected-public.json", &expected)?;
    println!("aggregation: fixtures/aggregation/input.json (+ expected-public.json)  notesRoot={}", input.notes_root);
    Ok(())
}

// ── pending-notes-commitment(5,30) ────────────────────────────────────────────

fn gen_pending(root: &Value) -> anyhow::Result<()> {
    const BATCH_SIZE: usize = 5;
    let w = &root["withdrawal"];
    let a = &root["aggregation"];
    let wd_notes: Vec<Note> = w["notes"].as_array().unwrap().iter().map(note_of).collect();
    let agg_in: Vec<Note> = a["inputNotes"].as_array().unwrap().iter().map(note_of).collect();
    let agg_out: Vec<Note> = a["outputNotes"].as_array().unwrap().iter().map(note_of).collect();
    let agg_fee = note_of(&a["feeNote"]);

    // Pre-existing global tree: the two withdrawal note ids (currentNoteIndex = 2).
    let initial_leaves: Vec<Fr> = wd_notes.iter().map(|n| n.id()).collect();
    let tree = Imt::from_leaves(TREE_DEPTH, &initial_leaves);

    // A full batch of 5 real, distinct, non-zero pending note ids to be committed into
    // the global IMT (the aggregation's inputs + outputs + fee note).
    let pending_ids: Vec<Fr> = vec![
        agg_in[0].id(),
        agg_in[1].id(),
        agg_out[0].id(),
        agg_out[1].id(),
        agg_fee.id(),
    ];

    let witness = build_pending_commitment(&tree, TREE_DEPTH, BATCH_SIZE, &pending_ids);

    // Derive the *circuit* input from the builder's flat object. The deployed
    // VerifyPendingNotesCommitment(5,30) declares exactly five input signals
    // [currentNoteIndex, inputHash, currentNotesRoot, pendingNoteIds, siblings].
    // `build_pending_commitment`'s object needs two adjustments to be directly
    // consumable by circom-witnesscalc/snarkjs (see README "witness-builder findings"):
    //   1. Drop `newNotesRoot` — a computed value the builder exposes, but NOT a
    //      circuit signal (snarkjs: "Too many values for input signal newNotesRoot").
    //   2. Field-reduce `inputHash` — the builder emits the RAW sha256BigInt digest
    //      (can exceed the modulus; circom-witnesscalc rejects it as overflow). The
    //      circuit's MultiInputSha256 output is `Bits2Num(256) mod p`, so the input
    //      signal is the digest reduced mod p.
    let reduced_input_hash = fr_to_dec(&fr_from_dec(&witness.input_hash));
    let mut input = serde_json::to_value(&witness)?;
    let map = input.as_object_mut().expect("witness serializes to an object");
    map.remove("newNotesRoot");
    map.insert("inputHash".into(), Value::String(reduced_input_hash.clone()));

    // Single public signal: inputHash (reduced).
    let expected: Vec<String> = vec![reduced_input_hash.clone()];

    let dir = fixtures_dir().join("pending");
    write_fixture(&dir, "input.json", &input)?;
    write_fixture(&dir, "expected-public.json", &expected)?;
    println!("pending:     fixtures/pending/input.json (+ expected-public.json)  inputHash={reduced_input_hash}");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let root: Value = serde_json::from_str(VECTORS)?;
    gen_withdrawal(&root)?;
    gen_aggregation(&root)?;
    gen_pending(&root)?;
    Ok(())
}
