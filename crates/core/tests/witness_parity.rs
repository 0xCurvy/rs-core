//! Production-compatibility vectors for the native Rust witness builders. The
//! Rust flat snarkjs input object must match Curvy's committed reference shape.

use curvy_core::field::{Fr, fr_from_dec};
use curvy_core::imt::Imt;
use curvy_core::witness::{
    Note, Proof, build_aggregation, build_pending_commitment, build_withdrawal,
};
use serde::Deserialize;
use serde_json::Value;

const JSON: &str = include_str!("../testdata/witness_vectors.json");

fn fr(s: &str) -> Fr {
    fr_from_dec(s)
}

#[derive(Deserialize)]
struct NoteJson {
    amount: String,
    token: String,
    #[serde(rename = "ownerPub")]
    owner_pub: [String; 2],
    #[serde(rename = "sharedSecret")]
    shared_secret: String,
    #[serde(rename = "ephemeralKey")]
    ephemeral_key: [String; 2],
    #[serde(rename = "viewTag")]
    view_tag: String,
}

#[derive(Deserialize)]
struct ProofJson {
    #[serde(rename = "leafIndex")]
    leaf_index: u64,
    siblings: Vec<String>,
}

fn note_of(j: &NoteJson) -> Note {
    Note {
        amount: fr(&j.amount),
        token: fr(&j.token),
        owner_pub: (fr(&j.owner_pub[0]), fr(&j.owner_pub[1])),
        shared_secret: fr(&j.shared_secret),
        ephemeral_key: (fr(&j.ephemeral_key[0]), fr(&j.ephemeral_key[1])),
        view_tag: fr(&j.view_tag),
    }
}

fn proof_of(j: &ProofJson) -> Proof {
    Proof {
        leaf_index: j.leaf_index,
        siblings: j.siblings.iter().map(|s| fr(s)).collect(),
    }
}

fn notes(v: &Value) -> Vec<Note> {
    let js: Vec<NoteJson> = serde_json::from_value(v.clone()).unwrap();
    js.iter().map(note_of).collect()
}
fn proofs(v: &Value) -> Vec<Proof> {
    let js: Vec<ProofJson> = serde_json::from_value(v.clone()).unwrap();
    js.iter().map(proof_of).collect()
}
fn pub_of(v: &Value) -> (Fr, Fr) {
    let p: [String; 2] = serde_json::from_value(v.clone()).unwrap();
    (fr(&p[0]), fr(&p[1]))
}
fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap().to_string()
}

#[test]
fn withdrawal_matches_ts() {
    let root: Value = serde_json::from_str(JSON).unwrap();
    let w = &root["withdrawal"];
    let rust = build_withdrawal(
        &notes(&w["notes"]),
        w["key"].as_str().unwrap(),
        pub_of(&w["publicKey"]),
        &proofs(&w["proofs"]),
        fr(&s(w, "notesRoot")),
        fr(&s(w, "destinationAddress")),
        fr(&s(w, "tokenId")),
    );
    assert_eq!(serde_json::to_value(&rust).unwrap(), w["flat"]);
}

#[test]
fn aggregation_matches_ts() {
    let root: Value = serde_json::from_str(JSON).unwrap();
    let a = &root["aggregation"];
    let output_notes = notes(&a["outputNotes"]);
    let fee_note = note_of(&serde_json::from_value(a["feeNote"].clone()).unwrap());
    let rust = build_aggregation(
        &notes(&a["inputNotes"]),
        &proofs(&a["inputProofs"]),
        &output_notes,
        &fee_note,
        a["key"].as_str().unwrap(),
        pub_of(&a["publicKey"]),
        fr(&s(a, "notesRoot")),
        fr(&s(a, "protocolFeePerThousand")),
        fr(&s(a, "gasFee")),
        pub_of(&a["feeNotePublicKey"]),
    );
    assert_eq!(serde_json::to_value(&rust).unwrap(), a["flat"]);
}

#[test]
fn pending_commitment_matches_ts() {
    let root: Value = serde_json::from_str(JSON).unwrap();
    let p = &root["pending"];
    let tree_depth = p["treeDepth"].as_u64().unwrap() as usize;
    let batch_size = p["batchSize"].as_u64().unwrap() as usize;
    let initial_leaves: Vec<Fr> = p["initialLeaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| fr(v.as_str().unwrap()))
        .collect();
    let pending_ids: Vec<Fr> = p["pendingNoteIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| fr(v.as_str().unwrap()))
        .collect();

    let tree = Imt::from_leaves(tree_depth, &initial_leaves);
    let rust = build_pending_commitment(&tree, tree_depth, batch_size, &pending_ids);
    assert_eq!(serde_json::to_value(&rust).unwrap(), p["flat"]);
}
