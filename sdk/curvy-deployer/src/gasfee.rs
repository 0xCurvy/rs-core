//! The depth-6 Poseidon2 commitment-gas-fee tree — the ONE arkworks-dependent piece
//! of the deployer, isolated behind the `gas-fee-tree` feature so a blokli fork can
//! drop `curvy-core` entirely (build `--no-default-features` and supply a precomputed
//! `commitment_fee_root` in `CurvyDeployConfig`).
//!
//! Ported verbatim from `poc/blokli-env/rs/src/bin/curvy-init.rs`. The leaf values are
//! passed in from the deployer's config (single source of truth), so this module holds
//! only the tree algorithm.

use alloy::primitives::U256;
use curvy_core::field::{fr_from_dec, fr_to_dec};
use curvy_core::poseidon::poseidon;
use curvy_core::Fr;

/// Depth of the per-token commitment gas-fee tree (== SDK `GAS_FEE_TREE_DEPTH`).
pub const GAS_FEE_TREE_DEPTH: usize = 6;

/// depth-6 Poseidon2 merkle root over a full 2^6=64-leaf set with `leaf[1]=leaf1_dec`,
/// `leaf[2]=leaf2_dec`, all others 0 — the `pendingNoteCommitment` leg placed BY TOKEN
/// ID. Identical to the SDK's `MerkleTree.fromOrderedLeaves({depth:6})`; byte-identical
/// to the on-chain `commitmentFeeRoot` the aggregation circuit binds.
pub fn commitment_fee_root(leaf1_dec: &str, leaf2_dec: &str) -> U256 {
    let n = 1usize << GAS_FEE_TREE_DEPTH; // 64
    let mut level: Vec<Fr> = vec![fr_from_dec("0"); n];
    level[1] = fr_from_dec(leaf1_dec);
    level[2] = fr_from_dec(leaf2_dec);
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| poseidon(&[pair[0], pair[1]]))
            .collect();
    }
    U256::from_str_radix(&fr_to_dec(&level[0]), 10).expect("root fits in U256")
}
