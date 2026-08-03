//! Golden-vector parity for the IMT + sharded tree vs `@zk-kit/imt` (which the SDK
//! `MerkleTree` / `ShardedNotesTree` wrap). The sharded witness is proven equal to
//! the flat IMT proof, so the same `@zk-kit` proofs are the oracle for both.

use curvy_core::field::{Fr, fr_from_dec, fr_to_dec};
use curvy_core::imt::{Imt, sharded_root, sharded_witness, verify_proof};
use serde::Deserialize;

#[derive(Deserialize)]
struct Proof {
    index: usize,
    siblings: Vec<String>,
}

#[derive(Deserialize)]
struct ImtVec {
    depth: usize,
    leaves: Vec<String>,
    root: String,
    proofs: Vec<Proof>,
}

#[derive(Deserialize)]
struct ShardedProof {
    #[serde(rename = "leafIndex")]
    leaf_index: usize,
    siblings: Vec<String>,
}

#[derive(Deserialize)]
struct ShardedVec {
    depth: usize,
    #[serde(rename = "shardHeight")]
    shard_height: usize,
    leaves: Vec<String>,
    root: String,
    witnesses: Vec<ShardedProof>,
}

fn fr(s: &str) -> Fr {
    fr_from_dec(s)
}
fn dec(siblings: &[Fr]) -> Vec<String> {
    siblings.iter().map(fr_to_dec).collect()
}

#[test]
fn imt_matches_zk_kit() {
    let vecs: Vec<ImtVec> =
        serde_json::from_str(include_str!("../testdata/imt_vectors.json")).unwrap();
    assert!(!vecs.is_empty());
    for v in &vecs {
        let leaves: Vec<Fr> = v.leaves.iter().map(|s| fr(s)).collect();

        let bulk = Imt::from_leaves(v.depth, &leaves);
        assert_eq!(
            fr_to_dec(&bulk.root()),
            v.root,
            "from_leaves root (depth {})",
            v.depth
        );

        let mut incremental = Imt::new(v.depth);
        for &l in &leaves {
            incremental.insert(l);
        }
        assert_eq!(
            fr_to_dec(&incremental.root()),
            v.root,
            "insert root (depth {})",
            v.depth
        );

        for p in &v.proofs {
            let proof = bulk.create_proof(p.index);
            assert_eq!(
                dec(&proof.siblings),
                p.siblings,
                "proof siblings (depth {}, leaf {})",
                v.depth,
                p.index
            );
            assert!(
                verify_proof(&proof),
                "proof verifies (depth {}, leaf {})",
                v.depth,
                p.index
            );
        }
    }
}

#[test]
fn sharded_matches_flat_imt() {
    let vecs: Vec<ShardedVec> =
        serde_json::from_str(include_str!("../testdata/sharded_vectors.json")).unwrap();
    assert!(!vecs.is_empty());
    for v in &vecs {
        let leaves: Vec<Fr> = v.leaves.iter().map(|s| fr(s)).collect();
        assert_eq!(
            fr_to_dec(&sharded_root(&leaves, v.depth, v.shard_height)),
            v.root,
            "sharded root (depth {}, shardHeight {})",
            v.depth,
            v.shard_height,
        );
        for w in &v.witnesses {
            let proof = sharded_witness(&leaves, w.leaf_index, v.depth, v.shard_height);
            assert_eq!(
                dec(&proof.siblings),
                w.siblings,
                "sharded witness (leaf {})",
                w.leaf_index
            );
            assert_eq!(fr_to_dec(&proof.root), v.root);
            assert!(
                verify_proof(&proof),
                "sharded witness verifies (leaf {})",
                w.leaf_index
            );
        }
    }
}
