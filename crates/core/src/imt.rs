//! Incremental Merkle tree (arity 2, Poseidon hash), matching the `@zk-kit/imt`
//! reference, plus a sharded-tree decomposition.
//!
//! The sharded tree cuts the tree at `shard_height`: leaves below the cut live in
//! fixed `2^shard_height`-leaf shards; the "cap" above is a small tree over the
//! completed shard roots. With zero-padding this is *exactly* equal to the flat IMT
//! over the same leaves, so the flat IMT proof is the reference for both
//! [`sharded_root`] and [`sharded_witness`].

use ark_ff::AdditiveGroup;

use crate::field::Fr;
use crate::poseidon::poseidon;

/// A depth-`d` inclusion proof: `siblings[level]` is the single sibling at each
/// level (arity 2), `index` is the leaf's global position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf: Fr,
    pub index: usize,
    pub siblings: Vec<Fr>,
    pub root: Fr,
}

/// `Z[h]` = root of an all-empty subtree of height `h` (`Z[0] = 0`), for `h` in
/// `0..=depth`. `Z[depth]` is the empty-tree root.
pub fn zero_roots(depth: usize) -> Vec<Fr> {
    let mut z = Vec::with_capacity(depth + 1);
    z.push(Fr::ZERO);
    for _ in 0..depth {
        let last = *z.last().unwrap();
        z.push(poseidon(&[last, last]));
    }
    z
}

/// Incremental Merkle Tree, arity 2, Poseidon(left, right) node hash.
#[derive(Clone)]
pub struct Imt {
    depth: usize,
    zeroes: Vec<Fr>,     // zeroes[level], len depth
    nodes: Vec<Vec<Fr>>, // nodes[level], len depth + 1
}

impl Imt {
    /// An empty tree of the given depth. `root()` is the empty-tree root `Z[depth]`.
    pub fn new(depth: usize) -> Self {
        let z = zero_roots(depth);
        let mut nodes = vec![Vec::new(); depth + 1];
        nodes[depth] = vec![z[depth]]; // root of the empty tree
        Self {
            depth,
            zeroes: z[..depth].to_vec(),
            nodes,
        }
    }

    /// Bulk-build from an ordered leaf log (O(n) hashes), like the `IMT` constructor.
    pub fn from_leaves(depth: usize, leaves: &[Fr]) -> Self {
        let mut t = Self::new(depth);
        if leaves.is_empty() {
            return t;
        }
        t.nodes[0] = leaves.to_vec();
        for level in 0..depth {
            let len = t.nodes[level].len();
            let mut parents = Vec::with_capacity(len.div_ceil(2));
            let mut index = 0;
            while index * 2 < len {
                let pos = index * 2;
                let left = t.nodes[level].get(pos).copied().unwrap_or(t.zeroes[level]);
                let right = t.nodes[level].get(pos + 1).copied().unwrap_or(t.zeroes[level]);
                parents.push(poseidon(&[left, right]));
                index += 1;
            }
            t.nodes[level + 1] = parents;
        }
        t
    }

    /// Append one leaf (incremental, O(depth) hashes). Produces the same tree as
    /// [`Self::from_leaves`] over the same leaf sequence.
    pub fn insert(&mut self, leaf: Fr) {
        let mut node = leaf;
        let mut index = self.nodes[0].len();
        for level in 0..self.depth {
            let pos = index % 2;
            let start = index - pos;
            // place `node` at nodes[level][index] (index == current len for an append)
            if index < self.nodes[level].len() {
                self.nodes[level][index] = node;
            } else {
                self.nodes[level].resize(index, self.zeroes[level]);
                self.nodes[level].push(node);
            }
            let left = self.nodes[level].get(start).copied().unwrap_or(self.zeroes[level]);
            let right = self.nodes[level].get(start + 1).copied().unwrap_or(self.zeroes[level]);
            node = poseidon(&[left, right]);
            index /= 2;
        }
        if self.nodes[self.depth].is_empty() {
            self.nodes[self.depth].push(node);
        } else {
            self.nodes[self.depth][0] = node;
        }
    }

    pub fn leaf_count(&self) -> usize {
        self.nodes[0].len()
    }

    pub fn root(&self) -> Fr {
        self.nodes[self.depth][0]
    }

    /// Inclusion proof for the leaf at `index` (`depth` siblings, bottom→top).
    pub fn create_proof(&self, index: usize) -> InclusionProof {
        assert!(index < self.nodes[0].len(), "imt: leaf index out of range");
        let leaf = self.nodes[0][index];
        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let sib_i = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
            let sib = self.nodes[level].get(sib_i).copied().unwrap_or(self.zeroes[level]);
            siblings.push(sib);
            idx /= 2;
        }
        InclusionProof {
            leaf,
            index,
            siblings,
            root: self.root(),
        }
    }
}

/// Verify an inclusion proof (bottom→top, `index` bit selects sibling side).
pub fn verify_proof(proof: &InclusionProof) -> bool {
    let mut node = proof.leaf;
    let mut idx = proof.index;
    for &sib in &proof.siblings {
        node = if idx.is_multiple_of(2) { poseidon(&[node, sib]) } else { poseidon(&[sib, node]) };
        idx >>= 1;
    }
    node == proof.root
}

// ── sharded decomposition (stateless; equals the flat IMT over the same leaves) ──

/// The cap level 0: one root per `2^shard_height`-leaf shard (the last shard may be
/// partial / "live").
fn shard_roots(leaves: &[Fr], shard_height: usize) -> Vec<Fr> {
    let shard_size = 1usize << shard_height;
    leaves
        .chunks(shard_size)
        .map(|chunk| Imt::from_leaves(shard_height, chunk).root())
        .collect()
}

/// Fold the cap up `cap_depth` levels, padding with `Z[shard_height + k]`. Returns
/// every level (level 0 = shard roots, top = global root).
fn cap_levels(shard_roots: Vec<Fr>, z: &[Fr], shard_height: usize, cap_depth: usize) -> Vec<Vec<Fr>> {
    let mut levels = vec![shard_roots];
    for k in 0..cap_depth {
        let h = shard_height + k;
        let level = &levels[k];
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { z[h] };
            next.push(poseidon(&[left, right]));
            i += 2;
        }
        levels.push(next);
    }
    levels
}

/// The global root of the sharded tree - equals `Imt::from_leaves(depth, leaves).root()`.
pub fn sharded_root(leaves: &[Fr], depth: usize, shard_height: usize) -> Fr {
    let z = zero_roots(depth);
    let cap_depth = depth - shard_height;
    let levels = cap_levels(shard_roots(leaves, shard_height), &z, shard_height, cap_depth);
    let top = &levels[cap_depth];
    if top.is_empty() {
        z[depth]
    } else {
        top[0]
    }
}

/// The full depth-`depth` inclusion proof for the leaf at `leaf_index`: the
/// within-shard siblings glued to the shared cap path - equals the flat IMT proof.
pub fn sharded_witness(leaves: &[Fr], leaf_index: usize, depth: usize, shard_height: usize) -> InclusionProof {
    let z = zero_roots(depth);
    let shard_size = 1usize << shard_height;
    let cap_depth = depth - shard_height;
    let shard_index = leaf_index >> shard_height;
    let within_index = leaf_index & (shard_size - 1);

    let shard_start = shard_index * shard_size;
    let shard_end = (shard_start + shard_size).min(leaves.len());
    let shard_leaves = &leaves[shard_start..shard_end];
    let mut siblings = Imt::from_leaves(shard_height, shard_leaves).create_proof(within_index).siblings;

    let levels = cap_levels(shard_roots(leaves, shard_height), &z, shard_height, cap_depth);
    let mut idx = shard_index;
    for k in 0..cap_depth {
        let row = &levels[k];
        let sib = idx ^ 1;
        siblings.push(if sib < row.len() { row[sib] } else { z[shard_height + k] });
        idx >>= 1;
    }

    let top = &levels[cap_depth];
    InclusionProof {
        leaf: leaves[leaf_index],
        index: leaf_index,
        siblings,
        root: if top.is_empty() { z[depth] } else { top[0] },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::fr_from_dec;

    #[test]
    fn empty_tree_root_depth_30() {
        // The protocol's EMPTY_TREE_ROOT (hash(0,0) folded 30×).
        assert_eq!(
            Imt::new(30).root(),
            fr_from_dec("4114686047564160449611603615418567457008101555090703535405891656262658644463"),
        );
    }

    #[test]
    fn insert_matches_from_leaves_and_proof_verifies() {
        let leaves: Vec<Fr> = (1u64..=11).map(Fr::from).collect();
        let mut incremental = Imt::new(6);
        for &l in &leaves {
            incremental.insert(l);
        }
        let bulk = Imt::from_leaves(6, &leaves);
        assert_eq!(incremental.root(), bulk.root());
        for i in 0..leaves.len() {
            let p = bulk.create_proof(i);
            assert!(verify_proof(&p));
            assert_eq!(p, incremental.create_proof(i));
        }
    }

    #[test]
    fn sharded_equals_flat() {
        let leaves: Vec<Fr> = (1u64..=20).map(Fr::from).collect();
        let (depth, shard_height) = (6, 2); // shard size 4 -> 5 shards
        let flat = Imt::from_leaves(depth, &leaves);
        assert_eq!(sharded_root(&leaves, depth, shard_height), flat.root());
        for i in 0..leaves.len() {
            assert_eq!(sharded_witness(&leaves, i, depth, shard_height), flat.create_proof(i));
        }
    }

    // Soundness: `verify_proof` must REJECT any tampered field - otherwise an
    // always-`true` verifier would still pass the round-trip tests above.
    #[test]
    fn verify_proof_rejects_tampering() {
        let leaves: Vec<Fr> = (1u64..=11).map(Fr::from).collect();
        let tree = Imt::from_leaves(6, &leaves);
        let one = Fr::from(1u64);

        for i in 0..leaves.len() {
            let good = tree.create_proof(i);
            assert!(verify_proof(&good), "valid proof must be accepted (leaf {i})");

            let mut bad_leaf = good.clone();
            bad_leaf.leaf += one;
            assert!(!verify_proof(&bad_leaf), "tampered leaf must be rejected (leaf {i})");

            let mut bad_sib = good.clone();
            bad_sib.siblings[0] += one;
            assert!(!verify_proof(&bad_sib), "tampered sibling must be rejected (leaf {i})");

            let mut bad_root = good.clone();
            bad_root.root += one;
            assert!(!verify_proof(&bad_root), "wrong root must be rejected (leaf {i})");

            // Flipping the index bit selects the sibling on the wrong side; only a
            // leaf whose flipped-index neighbour happens to be its mirror could
            // collide, which does not occur for this leaf set.
            let mut bad_index = good.clone();
            bad_index.index ^= 1;
            assert!(!verify_proof(&bad_index), "wrong index must be rejected (leaf {i})");
        }
    }
}
