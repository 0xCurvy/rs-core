//! Incremental Merkle Tree (arity 2, Poseidon hash) - a faithful port of
//! `@zk-kit/imt`'s `IMT`, plus indexed and stateful sharded engines.
//!
//! The sharded tree cuts the depth-30 tree at `shard_height`: leaves below the cut
//! live in fixed `2^shard_height`-leaf shards; the "cap" above is a small tree over
//! the completed shard roots. With zero-padding this is *exactly* equal to the flat
//! IMT over the same leaves. [`IndexedMerkleTree`] retains reverse lookup for the
//! generic/full-tree use cases. [`ShardedNotesTree`] retains only the live shard,
//! completed roots and owned paths. The stateless [`sharded_root`] and
//! [`sharded_witness`] helpers remain parity oracles.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::LazyLock;

use ark_ff::AdditiveGroup;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::field::{Fr, fr_from_be_32_checked, fr_to_be_32};
use crate::poseidon::poseidon;

/// Failure while mutating or restoring an incremental/sharded tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeError {
    InvalidGeometry { depth: usize, shard_height: usize },
    CapacityOverflow { depth: usize },
    TreeFull { depth: usize },
    DuplicateLeaf,
    LeafNotFound,
    LeafIndexOutOfRange { index: usize, leaf_count: usize },
    DuplicateOwnedLeaf { leaf_index: usize },
    OwnedLeafMismatch { leaf_index: usize },
    NoteNotMarked,
    NoteAlreadyCompleted { shard_index: usize },
    ShardNotCompleted { shard_index: usize },
    InvalidSiblingCount { expected: usize, actual: usize },
    WitnessRootMismatch { shard_index: usize },
    InvalidSnapshot(String),
    RewindBeforeCompleted { minimum: usize, requested: usize },
    NonCanonicalField,
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGeometry {
                depth,
                shard_height,
            } => {
                write!(
                    f,
                    "sharded tree: shard height must be in (0, {depth}); got {shard_height}"
                )
            }
            Self::CapacityOverflow { depth } => write!(
                f,
                "tree: depth {depth} does not fit this platform's index type"
            ),
            Self::TreeFull { depth } => write!(f, "tree: depth-{depth} tree is full"),
            Self::DuplicateLeaf => write!(f, "tree: leaf already exists"),
            Self::LeafNotFound => write!(f, "tree: leaf not found"),
            Self::LeafIndexOutOfRange { index, leaf_count } => {
                write!(
                    f,
                    "tree: leaf index {index} is out of range for {leaf_count} leaves"
                )
            }
            Self::DuplicateOwnedLeaf { leaf_index } => {
                write!(
                    f,
                    "sharded tree: more than one owned note is assigned to leaf {leaf_index}"
                )
            }
            Self::OwnedLeafMismatch { leaf_index } => {
                write!(
                    f,
                    "sharded tree: owned note does not match leaf {leaf_index}"
                )
            }
            Self::NoteNotMarked => write!(f, "sharded tree: note is not marked"),
            Self::NoteAlreadyCompleted { shard_index } => {
                write!(
                    f,
                    "sharded tree: note is in completed shard {shard_index}; adopt a frozen witness"
                )
            }
            Self::ShardNotCompleted { shard_index } => {
                write!(f, "sharded tree: shard {shard_index} is not completed")
            }
            Self::InvalidSiblingCount { expected, actual } => {
                write!(
                    f,
                    "sharded tree: expected {expected} within-shard siblings, got {actual}"
                )
            }
            Self::WitnessRootMismatch { shard_index } => {
                write!(
                    f,
                    "sharded tree: witness does not hash to shard {shard_index}'s root"
                )
            }
            Self::InvalidSnapshot(message) => {
                write!(f, "sharded tree: invalid snapshot: {message}")
            }
            Self::RewindBeforeCompleted { minimum, requested } => write!(
                f,
                "sharded tree: cannot rewind completed shards in place (minimum {minimum}, requested {requested}); restore a checkpoint",
            ),
            Self::NonCanonicalField => {
                write!(
                    f,
                    "tree: value is not a canonical 32-byte BN254 field element"
                )
            }
        }
    }
}

impl std::error::Error for TreeError {}

/// A depth-`d` inclusion proof: `siblings[level]` is the single sibling at each
/// level (arity 2), `index` is the leaf's global position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf: Fr,
    pub index: usize,
    pub siblings: Vec<Fr>,
    pub root: Fr,
}

/// Depth of the production Curvy notes tree.
pub const NOTES_TREE_DEPTH: usize = 30;

/// Shard height of the production Curvy notes tree: a shard covers `2^14` leaves.
pub const NOTES_SHARD_HEIGHT: usize = 14;

/// Leaves per completed shard in the production notes tree (`1 << NOTES_SHARD_HEIGHT`).
pub const NOTES_SHARD_SIZE: usize = 1 << NOTES_SHARD_HEIGHT;

/// Schema version of the persisted notes-tree state. Bump only when the
/// persisted layout changes in a way that invalidates stored checkpoints.
pub const NOTES_TREE_VERSION: u32 = 1;

/// Largest depth served from the precomputed zero-root table. Every tree this
/// crate can construct is covered: `tree_capacity` rejects depths whose
/// `1 << depth` does not fit a `usize`.
const MAX_CACHED_ZERO_DEPTH: usize = 64;

/// The `Fr::ZERO`-leaf zero-root table, computed once.
///
/// `zero_roots_from` is a pure recurrence in which `z[i]` depends only on
/// `z[i - 1]`, so the table for any depth is a *prefix* of the table for a
/// larger depth. One table therefore serves every depth without changing a
/// single hash.
static ZERO_ROOTS: LazyLock<Vec<Fr>> =
    LazyLock::new(|| zero_roots_from(MAX_CACHED_ZERO_DEPTH, Fr::ZERO));

/// `Z[h]` = root of an all-empty subtree of height `h` (`Z[0] = 0`), for `h` in
/// `0..=depth`. `Z[depth]` is the empty-tree root.
///
/// Served from a precomputed table, so this is a copy rather than `depth`
/// Poseidon hashes. Restoring a depth-30 frontier was measured at 99.8%
/// zero-root recomputation before this cache existed.
pub fn zero_roots(depth: usize) -> Vec<Fr> {
    match ZERO_ROOTS.get(..=depth) {
        Some(prefix) => prefix.to_vec(),
        None => zero_roots_from(depth, Fr::ZERO),
    }
}

/// Zero roots starting from a caller-supplied leaf-level zero.
pub fn zero_roots_from(depth: usize, zero_leaf: Fr) -> Vec<Fr> {
    let mut z = Vec::with_capacity(depth + 1);
    z.push(zero_leaf);
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
    zero_leaf: Fr,
    zeroes: Vec<Fr>,     // zeroes[level], len depth
    nodes: Vec<Vec<Fr>>, // nodes[level], len depth + 1
}

impl Imt {
    /// An empty tree of the given depth. `root()` is the empty-tree root `Z[depth]`.
    pub fn new(depth: usize) -> Self {
        Self::new_with_zero(depth, Fr::ZERO)
    }

    /// An empty tree whose leaf-level zero is `zero_leaf`.
    ///
    /// The sharded tree uses this for its cap: an empty cap leaf represents an
    /// entire empty shard, so its zero is `Z[shard_height]`, not field zero.
    pub fn new_with_zero(depth: usize, zero_leaf: Fr) -> Self {
        let z = zero_roots_from(depth, zero_leaf);
        let mut nodes = vec![Vec::new(); depth + 1];
        nodes[depth] = vec![z[depth]]; // root of the empty tree
        Self {
            depth,
            zero_leaf,
            zeroes: z[..depth].to_vec(),
            nodes,
        }
    }

    /// Bulk-build from an ordered leaf log (O(n) hashes), like the `IMT` constructor.
    pub fn from_leaves(depth: usize, leaves: &[Fr]) -> Self {
        Self::from_leaves_with_zero(depth, Fr::ZERO, leaves)
    }

    /// Bulk-build with a caller-supplied leaf-level zero value.
    pub fn from_leaves_with_zero(depth: usize, zero_leaf: Fr, leaves: &[Fr]) -> Self {
        let mut t = Self::new_with_zero(depth, zero_leaf);
        if leaves.is_empty() {
            return t;
        }
        t.nodes[0] = leaves.to_vec();
        for level in 0..depth {
            t.nodes[level + 1] = build_parent_level(&t.nodes[level], t.zeroes[level]);
        }
        t
    }

    /// Append one leaf (incremental, O(depth) hashes). Produces the same tree as
    /// [`Self::from_leaves`] over the same leaf sequence.
    pub fn insert(&mut self, leaf: Fr) {
        debug_assert!(self.nodes[0].len() < self.capacity().unwrap_or(usize::MAX));
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
            let left = self.nodes[level]
                .get(start)
                .copied()
                .unwrap_or(self.zeroes[level]);
            let right = self.nodes[level]
                .get(start + 1)
                .copied()
                .unwrap_or(self.zeroes[level]);
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

    pub fn capacity(&self) -> Result<usize, TreeError> {
        1usize
            .checked_shl(self.depth as u32)
            .ok_or(TreeError::CapacityOverflow { depth: self.depth })
    }

    pub fn leaf(&self, index: usize) -> Option<Fr> {
        self.nodes[0].get(index).copied()
    }

    /// Replace an existing leaf and re-hash only its path to the root.
    pub fn update(&mut self, index: usize, leaf: Fr) -> Result<(), TreeError> {
        let leaf_count = self.leaf_count();
        if index >= leaf_count {
            return Err(TreeError::LeafIndexOutOfRange { index, leaf_count });
        }

        self.nodes[0][index] = leaf;
        let mut node_index = index;
        for level in 0..self.depth {
            let pair_start = node_index & !1;
            let left = self.nodes[level]
                .get(pair_start)
                .copied()
                .unwrap_or(self.zeroes[level]);
            let right = self.nodes[level]
                .get(pair_start + 1)
                .copied()
                .unwrap_or(self.zeroes[level]);
            node_index >>= 1;
            self.nodes[level + 1][node_index] = poseidon(&[left, right]);
        }
        Ok(())
    }

    /// Drop a suffix of leaves and bulk-rebuild the remaining tree.
    pub fn truncate(&mut self, leaf_count: usize) -> Result<(), TreeError> {
        let current = self.leaf_count();
        if leaf_count > current {
            return Err(TreeError::LeafIndexOutOfRange {
                index: leaf_count,
                leaf_count: current,
            });
        }
        let leaves = self.nodes[0][..leaf_count].to_vec();
        *self = Self::from_leaves_with_zero(self.depth, self.zero_leaf, &leaves);
        Ok(())
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
            let sib_i = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            let sib = self.nodes[level]
                .get(sib_i)
                .copied()
                .unwrap_or(self.zeroes[level]);
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

const FRONTIER_SNAPSHOT_MAGIC: &[u8; 8] = b"CVYFRONT";
const FRONTIER_SNAPSHOT_VERSION: u8 = 1;
const FRONTIER_SNAPSHOT_HEADER_LEN: usize = 24;

/// A completed fixed-height subtree emitted while appending to [`NotesFrontier`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedShard {
    pub shard_index: usize,
    pub root: Fr,
}

/// Result of one append to [`NotesFrontier`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontierAppend {
    pub leaf_index: usize,
    pub completed_shard: Option<CompletedShard>,
}

/// Constant-space append frontier.
///
/// Unlike [`ShardedNotesTree`], this type retains no leaves, cap, reverse index,
/// or owned-note witnesses. `frontier[level]` is the completed subtree covering
/// the rightmost set bit of `leaf_count`; the optional slot at `depth` holds the
/// root only when the tree is completely full. A depth-30 snapshot is at most
/// 1,015 bytes and is therefore cheap to persist once per hot block for reorg
/// rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotesFrontier {
    depth: usize,
    shard_height: usize,
    shard_size: usize,
    leaf_count: usize,
    frontier: Vec<Option<Fr>>,
    zeroes: Vec<Fr>,
}

impl NotesFrontier {
    pub fn new(depth: usize, shard_height: usize) -> Result<Self, TreeError> {
        if shard_height == 0 || shard_height >= depth {
            return Err(TreeError::InvalidGeometry {
                depth,
                shard_height,
            });
        }
        let shard_size = tree_capacity(shard_height)?;
        tree_capacity(depth)?;
        Ok(Self {
            depth,
            shard_height,
            shard_size,
            leaf_count: 0,
            frontier: vec![None; depth + 1],
            zeroes: zero_roots(depth),
        })
    }

    /// An empty frontier with the production notes-tree geometry
    /// ([`NOTES_TREE_DEPTH`] / [`NOTES_SHARD_HEIGHT`]).
    ///
    /// Infallible: the protocol geometry is a compile-time constant that
    /// [`NotesFrontier::new`] accepts, which `production_geometry_is_valid`
    /// asserts.
    pub fn production() -> Self {
        Self::new(NOTES_TREE_DEPTH, NOTES_SHARD_HEIGHT)
            .expect("production notes-tree geometry is valid")
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn shard_height(&self) -> usize {
        self.shard_height
    }

    pub fn shard_size(&self) -> usize {
        self.shard_size
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Number of *completed* shards: `leaf_count >> shard_height`.
    ///
    /// A partially filled trailing shard is not counted, so this is exactly the
    /// number of shard roots emitted by [`NotesFrontier::append`] so far.
    pub fn shard_count(&self) -> usize {
        self.leaf_count >> self.shard_height
    }

    /// The depth-`depth` root using the protocol's recursive zero padding.
    pub fn root(&self) -> Fr {
        let capacity = tree_capacity(self.depth).unwrap_or(usize::MAX);
        if self.leaf_count == capacity {
            return self.frontier[self.depth].unwrap_or(self.zeroes[self.depth]);
        }

        let mut node = self.zeroes[0];
        let mut occupied = self.leaf_count;
        for level in 0..self.depth {
            node = if occupied & 1 == 1 {
                let left = self.frontier[level].unwrap_or(self.zeroes[level]);
                poseidon(&[left, node])
            } else {
                poseidon(&[node, self.zeroes[level]])
            };
            occupied >>= 1;
        }
        node
    }

    /// Append one leaf in O(depth), returning an emitted shard root exactly when
    /// this leaf completes a `2^shard_height` subtree.
    pub fn append(&mut self, leaf: Fr) -> Result<FrontierAppend, TreeError> {
        let capacity = tree_capacity(self.depth)?;
        if self.leaf_count >= capacity {
            return Err(TreeError::TreeFull { depth: self.depth });
        }

        let leaf_index = self.leaf_count;
        let mut cursor = leaf_index;
        let mut node = leaf;
        let mut completed_shard = None;

        for level in 0..=self.depth {
            if cursor & 1 == 0 {
                self.frontier[level] = Some(node);
                break;
            }

            let left = self.frontier[level].take().ok_or_else(|| {
                TreeError::InvalidSnapshot(format!(
                    "frontier level {level} is empty for occupied leaf-count bit",
                ))
            })?;
            node = poseidon(&[left, node]);
            cursor >>= 1;

            if level + 1 == self.shard_height {
                completed_shard = Some(CompletedShard {
                    shard_index: leaf_index >> self.shard_height,
                    root: node,
                });
            }
        }

        self.leaf_count += 1;
        Ok(FrontierAppend {
            leaf_index,
            completed_shard,
        })
    }

    /// Append a packed logical batch atomically with respect to capacity checks.
    /// Only completed shard descriptors are returned; leaf indices remain dense
    /// from the pre-append `leaf_count`.
    pub fn append_many(&mut self, leaves: &[Fr]) -> Result<Vec<CompletedShard>, TreeError> {
        let capacity = tree_capacity(self.depth)?;
        if leaves.len() > capacity.saturating_sub(self.leaf_count) {
            return Err(TreeError::TreeFull { depth: self.depth });
        }

        let mut completed = Vec::new();
        for leaf in leaves {
            if let Some(shard) = self.append(*leaf)?.completed_shard {
                completed.push(shard);
            }
        }
        Ok(completed)
    }

    /// [`NotesFrontier::append`] over a canonical big-endian 32-byte leaf.
    ///
    /// Every consumer reaching this type across a byte boundary - the wasm/TS
    /// boundary otherwise repeats the same `fr_from_be_32_checked` marshalling.
    /// Rejects non-canonical encodings rather than reducing them into the field.
    pub fn append_be_32(&mut self, leaf: &[u8; 32]) -> Result<FrontierAppend, TreeError> {
        let leaf = fr_from_be_32_checked(leaf).ok_or(TreeError::NonCanonicalField)?;
        self.append(leaf)
    }

    /// [`NotesFrontier::root`] as canonical big-endian 32 bytes.
    pub fn root_be_32(&self) -> [u8; 32] {
        fr_to_be_32(&self.root())
    }

    /// Canonical versioned snapshot suitable for a per-block database checkpoint.
    pub fn encode_snapshot(&self) -> Vec<u8> {
        let present = self.frontier.iter().filter(|slot| slot.is_some()).count();
        let mut bytes =
            Vec::with_capacity(FRONTIER_SNAPSHOT_HEADER_LEN + self.frontier.len() + present * 32);
        bytes.extend_from_slice(FRONTIER_SNAPSHOT_MAGIC);
        bytes.push(FRONTIER_SNAPSHOT_VERSION);
        bytes.push(self.depth as u8);
        bytes.push(self.shard_height as u8);
        bytes.push(0);
        bytes.extend_from_slice(&(self.leaf_count as u64).to_be_bytes());
        bytes.extend_from_slice(&(self.frontier.len() as u32).to_be_bytes());
        for slot in &self.frontier {
            match slot {
                Some(field) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&fr_to_be_32(field));
                }
                None => bytes.push(0),
            }
        }
        bytes
    }

    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, TreeError> {
        if bytes.len() < FRONTIER_SNAPSHOT_HEADER_LEN {
            return Err(TreeError::InvalidSnapshot(
                "frontier snapshot header is truncated".to_owned(),
            ));
        }
        if bytes.get(..8) != Some(FRONTIER_SNAPSHOT_MAGIC.as_slice()) {
            return Err(TreeError::InvalidSnapshot(
                "invalid frontier snapshot magic".to_owned(),
            ));
        }
        if bytes[8] != FRONTIER_SNAPSHOT_VERSION {
            return Err(TreeError::InvalidSnapshot(format!(
                "unsupported frontier snapshot version {}",
                bytes[8],
            )));
        }
        if bytes[11] != 0 {
            return Err(TreeError::InvalidSnapshot(
                "frontier snapshot reserved byte is non-zero".to_owned(),
            ));
        }

        let depth = bytes[9] as usize;
        let shard_height = bytes[10] as usize;
        let raw_leaf_count: [u8; 8] = bytes[12..20]
            .try_into()
            .map_err(|_| TreeError::InvalidSnapshot("invalid frontier leaf count".to_owned()))?;
        let leaf_count = usize::try_from(u64::from_be_bytes(raw_leaf_count)).map_err(|_| {
            TreeError::InvalidSnapshot("frontier leaf count exceeds this platform".to_owned())
        })?;
        let raw_slot_count: [u8; 4] = bytes[20..24]
            .try_into()
            .map_err(|_| TreeError::InvalidSnapshot("invalid frontier slot count".to_owned()))?;
        let slot_count = u32::from_be_bytes(raw_slot_count) as usize;

        let mut tree = Self::new(depth, shard_height)?;
        let capacity = tree_capacity(depth)?;
        if leaf_count > capacity {
            return Err(TreeError::InvalidSnapshot(format!(
                "frontier leaf count {leaf_count} exceeds capacity {capacity}",
            )));
        }
        if slot_count != depth + 1 {
            return Err(TreeError::InvalidSnapshot(format!(
                "frontier snapshot has {slot_count} slots; expected {}",
                depth + 1,
            )));
        }

        let mut cursor = FRONTIER_SNAPSHOT_HEADER_LEN;
        for level in 0..slot_count {
            let flag = *bytes.get(cursor).ok_or_else(|| {
                TreeError::InvalidSnapshot("truncated frontier slot flag".to_owned())
            })?;
            cursor += 1;
            tree.frontier[level] = match flag {
                0 => None,
                1 => Some(read_field(bytes, &mut cursor)?),
                _ => {
                    return Err(TreeError::InvalidSnapshot(format!(
                        "invalid frontier slot flag {flag}",
                    )));
                }
            };

            let should_be_present = (leaf_count >> level) & 1 == 1;
            if tree.frontier[level].is_some() != should_be_present {
                return Err(TreeError::InvalidSnapshot(format!(
                    "frontier slot {level} does not match leaf count {leaf_count}",
                )));
            }
        }
        if cursor != bytes.len() {
            return Err(TreeError::InvalidSnapshot(
                "trailing frontier snapshot bytes".to_owned(),
            ));
        }

        tree.leaf_count = leaf_count;
        Ok(tree)
    }
}

fn build_parent_level(level: &[Fr], zero: Fr) -> Vec<Fr> {
    #[cfg(feature = "parallel")]
    {
        level
            .par_chunks(2)
            .map(|pair| poseidon(&[pair[0], pair.get(1).copied().unwrap_or(zero)]))
            .collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        level
            .chunks(2)
            .map(|pair| poseidon(&[pair[0], pair.get(1).copied().unwrap_or(zero)]))
            .collect()
    }
}

/// Incremental Merkle tree with a reverse leaf index.
///
/// The sharded wallet path normally uses [`ShardedNotesTree`]; this indexed form
/// is for cold-shard recovery, pending-note witness generation and the full-tree
/// profile.
#[derive(Clone)]
pub struct IndexedMerkleTree {
    tree: Imt,
    indices: HashMap<Fr, usize>,
}

/// Position-addressed Merkle tree that deliberately permits duplicate leaves.
///
/// Gas-fee trees are keyed by token index rather than leaf value, so two tokens
/// may legitimately have the same fee. Keep this separate from
/// [`IndexedMerkleTree`] so note trees retain their duplicate-rejection invariant.
#[derive(Clone)]
pub struct OrderedMerkleTree {
    tree: Imt,
}

impl OrderedMerkleTree {
    pub fn new(depth: usize) -> Result<Self, TreeError> {
        tree_capacity(depth)?;
        Ok(Self {
            tree: Imt::new(depth),
        })
    }

    pub fn from_leaves(depth: usize, leaves: &[Fr]) -> Result<Self, TreeError> {
        let capacity = tree_capacity(depth)?;
        if leaves.len() > capacity {
            return Err(TreeError::TreeFull { depth });
        }
        Ok(Self {
            tree: Imt::from_leaves(depth, leaves),
        })
    }

    pub fn depth(&self) -> usize {
        self.tree.depth
    }

    pub fn leaf_count(&self) -> usize {
        self.tree.leaf_count()
    }

    pub fn root(&self) -> Fr {
        self.tree.root()
    }

    pub fn insert(&mut self, leaf: Fr) -> Result<usize, TreeError> {
        if self.leaf_count() >= self.tree.capacity()? {
            return Err(TreeError::TreeFull {
                depth: self.depth(),
            });
        }
        let index = self.leaf_count();
        self.tree.insert(leaf);
        Ok(index)
    }

    pub fn insert_many(&mut self, leaves: &[Fr]) -> Result<(), TreeError> {
        if leaves.len() > self.tree.capacity()?.saturating_sub(self.leaf_count()) {
            return Err(TreeError::TreeFull {
                depth: self.depth(),
            });
        }
        for leaf in leaves {
            self.tree.insert(*leaf);
        }
        Ok(())
    }

    pub fn create_proof_at(&self, index: usize) -> Result<InclusionProof, TreeError> {
        if index >= self.leaf_count() {
            return Err(TreeError::LeafIndexOutOfRange {
                index,
                leaf_count: self.leaf_count(),
            });
        }
        Ok(self.tree.create_proof(index))
    }
}

impl IndexedMerkleTree {
    pub fn new(depth: usize) -> Result<Self, TreeError> {
        tree_capacity(depth)?;
        Ok(Self {
            tree: Imt::new(depth),
            indices: HashMap::new(),
        })
    }

    pub fn from_leaves(depth: usize, leaves: &[Fr]) -> Result<Self, TreeError> {
        let capacity = tree_capacity(depth)?;
        if leaves.len() > capacity {
            return Err(TreeError::TreeFull { depth });
        }
        let mut indices = HashMap::with_capacity(leaves.len());
        for (index, leaf) in leaves.iter().copied().enumerate() {
            if indices.insert(leaf, index).is_some() {
                return Err(TreeError::DuplicateLeaf);
            }
        }
        Ok(Self {
            tree: Imt::from_leaves(depth, leaves),
            indices,
        })
    }

    pub fn depth(&self) -> usize {
        self.tree.depth
    }

    pub fn leaf_count(&self) -> usize {
        self.tree.leaf_count()
    }

    pub fn leaves(&self) -> &[Fr] {
        &self.tree.nodes[0]
    }

    pub fn root(&self) -> Fr {
        self.tree.root()
    }

    pub fn get_index(&self, leaf: Fr) -> Option<usize> {
        self.indices.get(&leaf).copied()
    }

    pub fn insert(&mut self, leaf: Fr) -> Result<usize, TreeError> {
        if self.indices.contains_key(&leaf) {
            return Err(TreeError::DuplicateLeaf);
        }
        if self.leaf_count() >= self.tree.capacity()? {
            return Err(TreeError::TreeFull {
                depth: self.depth(),
            });
        }
        let index = self.leaf_count();
        self.tree.insert(leaf);
        self.indices.insert(leaf, index);
        Ok(index)
    }

    pub fn insert_many(&mut self, leaves: &[Fr]) -> Result<(), TreeError> {
        if leaves.len() > self.tree.capacity()?.saturating_sub(self.leaf_count()) {
            return Err(TreeError::TreeFull {
                depth: self.depth(),
            });
        }
        let mut incoming = HashSet::with_capacity(leaves.len());
        for leaf in leaves {
            if self.indices.contains_key(leaf) || !incoming.insert(*leaf) {
                return Err(TreeError::DuplicateLeaf);
            }
        }
        for leaf in leaves {
            self.insert(*leaf)?;
        }
        Ok(())
    }

    pub fn create_proof(&self, leaf: Fr) -> Result<InclusionProof, TreeError> {
        let index = self.get_index(leaf).ok_or(TreeError::LeafNotFound)?;
        Ok(self.tree.create_proof(index))
    }

    pub fn create_proof_at(&self, index: usize) -> Result<InclusionProof, TreeError> {
        if index >= self.leaf_count() {
            return Err(TreeError::LeafIndexOutOfRange {
                index,
                leaf_count: self.leaf_count(),
            });
        }
        Ok(self.tree.create_proof(index))
    }

    pub fn truncate(&mut self, leaf_count: usize) -> Result<(), TreeError> {
        if leaf_count > self.leaf_count() {
            return Err(TreeError::LeafIndexOutOfRange {
                index: leaf_count,
                leaf_count: self.leaf_count(),
            });
        }
        let removed: Vec<Fr> = self.leaves()[leaf_count..].to_vec();
        self.tree.truncate(leaf_count)?;
        for leaf in removed {
            self.indices.remove(&leaf);
        }
        Ok(())
    }
}

/// Verify an inclusion proof (bottom→top, `index` bit selects sibling side).
pub fn verify_proof(proof: &InclusionProof) -> bool {
    let mut node = proof.leaf;
    let mut idx = proof.index;
    for &sib in &proof.siblings {
        node = if idx.is_multiple_of(2) {
            poseidon(&[node, sib])
        } else {
            poseidon(&[sib, node])
        };
        idx >>= 1;
    }
    node == proof.root
}

// ── stateful sharded tree (bounded live shard + mutable cap) ────────────────

/// Persisted witness state for one owned note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedNoteWitness {
    pub note_id: Fr,
    pub leaf_index: usize,
    /// Frozen once the note's shard completes; derived from the live tree before then.
    pub within_shard_siblings: Option<Vec<Fr>>,
}

/// Minimal state needed to restore a [`ShardedNotesTree`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardedTreeSnapshot {
    pub depth: usize,
    pub shard_height: usize,
    pub completed_roots: Vec<Fr>,
    pub live_leaves: Vec<Fr>,
    pub owned_notes: Vec<OwnedNoteWitness>,
}

const SNAPSHOT_MAGIC: [u8; 4] = *b"CYST";
const SNAPSHOT_VERSION: u8 = 1;
const SNAPSHOT_HEADER_LEN: usize = 20;

impl ShardedTreeSnapshot {
    /// Encode a deterministic, versioned binary snapshot.
    ///
    /// Field elements use canonical 32-byte big-endian encoding. Chain identity,
    /// block hash and sync cursor intentionally remain storage-layer metadata, so
    /// this blob can be embedded in any caller's checkpoint format.
    pub fn encode(&self) -> Result<Vec<u8>, TreeError> {
        if self.shard_height == 0 || self.shard_height >= self.depth {
            return Err(TreeError::InvalidGeometry {
                depth: self.depth,
                shard_height: self.shard_height,
            });
        }
        let shard_size = tree_capacity(self.shard_height)?;
        let max_shards = tree_capacity(self.depth - self.shard_height)?;
        if self.completed_roots.len() > max_shards {
            return Err(TreeError::InvalidSnapshot(
                "too many completed shard roots".to_owned(),
            ));
        }
        if self.live_leaves.len() >= shard_size {
            return Err(TreeError::InvalidSnapshot(
                "the live shard must contain fewer than one complete shard".to_owned(),
            ));
        }
        if self.completed_roots.len() == max_shards && !self.live_leaves.is_empty() {
            return Err(TreeError::InvalidSnapshot(
                "live leaves exceed the tree capacity".to_owned(),
            ));
        }
        let depth: u8 = self.depth.try_into().map_err(|_| {
            TreeError::InvalidSnapshot("depth does not fit the snapshot format".to_owned())
        })?;
        let shard_height: u8 = self.shard_height.try_into().map_err(|_| {
            TreeError::InvalidSnapshot("shard height does not fit the snapshot format".to_owned())
        })?;
        let completed_count: u32 = self
            .completed_roots
            .len()
            .try_into()
            .map_err(|_| TreeError::InvalidSnapshot("too many completed roots".to_owned()))?;
        let live_count: u32 = self
            .live_leaves
            .len()
            .try_into()
            .map_err(|_| TreeError::InvalidSnapshot("too many live leaves".to_owned()))?;
        let owned_count: u32 = self
            .owned_notes
            .len()
            .try_into()
            .map_err(|_| TreeError::InvalidSnapshot("too many owned notes".to_owned()))?;

        let siblings_count: usize = self
            .owned_notes
            .iter()
            .map(|owned| owned.within_shard_siblings.as_ref().map_or(0, Vec::len))
            .sum();
        let fields_count = self
            .completed_roots
            .len()
            .checked_add(self.live_leaves.len())
            .and_then(|count| count.checked_add(self.owned_notes.len()))
            .and_then(|count| count.checked_add(siblings_count))
            .ok_or_else(|| TreeError::InvalidSnapshot("snapshot size overflow".to_owned()))?;
        let owned_metadata_bytes = self
            .owned_notes
            .len()
            .checked_mul(8)
            .ok_or_else(|| TreeError::InvalidSnapshot("snapshot size overflow".to_owned()))?;
        let byte_capacity =
            SNAPSHOT_HEADER_LEN
                .checked_add(fields_count.checked_mul(32).ok_or_else(|| {
                    TreeError::InvalidSnapshot("snapshot size overflow".to_owned())
                })?)
                .and_then(|size| size.checked_add(owned_metadata_bytes))
                .ok_or_else(|| TreeError::InvalidSnapshot("snapshot size overflow".to_owned()))?;
        let mut bytes = Vec::with_capacity(byte_capacity);
        bytes.extend_from_slice(&SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&[SNAPSHOT_VERSION, depth, shard_height, 0]);
        bytes.extend_from_slice(&completed_count.to_be_bytes());
        bytes.extend_from_slice(&live_count.to_be_bytes());
        bytes.extend_from_slice(&owned_count.to_be_bytes());
        append_fields(&mut bytes, &self.completed_roots);
        append_fields(&mut bytes, &self.live_leaves);

        for owned in &self.owned_notes {
            bytes.extend_from_slice(&fr_to_be_32(&owned.note_id));
            let leaf_index: u32 = owned.leaf_index.try_into().map_err(|_| {
                TreeError::InvalidSnapshot("leaf index does not fit u32".to_owned())
            })?;
            bytes.extend_from_slice(&leaf_index.to_be_bytes());
            bytes.push(u8::from(owned.within_shard_siblings.is_some()));
            bytes.extend_from_slice(&[0; 3]);
            if let Some(siblings) = &owned.within_shard_siblings {
                if siblings.len() != self.shard_height {
                    return Err(TreeError::InvalidSiblingCount {
                        expected: self.shard_height,
                        actual: siblings.len(),
                    });
                }
                append_fields(&mut bytes, siblings);
            }
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        if bytes.len() < SNAPSHOT_HEADER_LEN {
            return Err(TreeError::InvalidSnapshot("truncated header".to_owned()));
        }
        if bytes[..4] != SNAPSHOT_MAGIC {
            return Err(TreeError::InvalidSnapshot("bad magic".to_owned()));
        }
        if bytes[4] != SNAPSHOT_VERSION {
            return Err(TreeError::InvalidSnapshot(format!(
                "unsupported version {}",
                bytes[4],
            )));
        }
        if bytes[7] != 0 {
            return Err(TreeError::InvalidSnapshot(
                "reserved header byte is non-zero".to_owned(),
            ));
        }

        let depth = usize::from(bytes[5]);
        let shard_height = usize::from(bytes[6]);
        if shard_height == 0 || shard_height >= depth {
            return Err(TreeError::InvalidGeometry {
                depth,
                shard_height,
            });
        }
        let completed_count = read_u32(bytes, 8)? as usize;
        let live_count = read_u32(bytes, 12)? as usize;
        let owned_count = read_u32(bytes, 16)? as usize;
        let shard_size = tree_capacity(shard_height)?;
        let max_shards = tree_capacity(depth - shard_height)?;
        if completed_count > max_shards {
            return Err(TreeError::InvalidSnapshot(
                "too many completed shard roots".to_owned(),
            ));
        }
        if live_count >= shard_size {
            return Err(TreeError::InvalidSnapshot(
                "the live shard must contain fewer than one complete shard".to_owned(),
            ));
        }
        if completed_count == max_shards && live_count != 0 {
            return Err(TreeError::InvalidSnapshot(
                "live leaves exceed the tree capacity".to_owned(),
            ));
        }

        let fixed_field_count = completed_count
            .checked_add(live_count)
            .ok_or_else(|| TreeError::InvalidSnapshot("field count overflow".to_owned()))?;
        let fixed_bytes = fixed_field_count
            .checked_mul(32)
            .ok_or_else(|| TreeError::InvalidSnapshot("field byte count overflow".to_owned()))?;
        if fixed_bytes > bytes.len() - SNAPSHOT_HEADER_LEN {
            return Err(TreeError::InvalidSnapshot(
                "truncated root/leaf fields".to_owned(),
            ));
        }
        let minimum_owned_bytes = owned_count.checked_mul(40).ok_or_else(|| {
            TreeError::InvalidSnapshot("owned-note byte count overflow".to_owned())
        })?;
        if minimum_owned_bytes > bytes.len() - SNAPSHOT_HEADER_LEN - fixed_bytes {
            return Err(TreeError::InvalidSnapshot(
                "truncated owned-note records".to_owned(),
            ));
        }

        let mut cursor = SNAPSHOT_HEADER_LEN;
        let completed_roots = read_fields(bytes, &mut cursor, completed_count)?;
        let live_leaves = read_fields(bytes, &mut cursor, live_count)?;
        let mut owned_notes = Vec::with_capacity(owned_count);
        for _ in 0..owned_count {
            let note_id = read_field(bytes, &mut cursor)?;
            let leaf_index = read_u32_at_cursor(bytes, &mut cursor)? as usize;
            let flag = *bytes.get(cursor).ok_or_else(|| {
                TreeError::InvalidSnapshot("truncated owned-note flag".to_owned())
            })?;
            cursor += 1;
            let reserved = bytes.get(cursor..cursor + 3).ok_or_else(|| {
                TreeError::InvalidSnapshot("truncated owned-note padding".to_owned())
            })?;
            if reserved != [0, 0, 0] {
                return Err(TreeError::InvalidSnapshot(
                    "owned-note padding is non-zero".to_owned(),
                ));
            }
            cursor += 3;
            let within_shard_siblings = match flag {
                0 => None,
                1 => Some(read_fields(bytes, &mut cursor, shard_height)?),
                _ => {
                    return Err(TreeError::InvalidSnapshot(format!(
                        "invalid frozen-path flag {flag}"
                    )));
                }
            };
            owned_notes.push(OwnedNoteWitness {
                note_id,
                leaf_index,
                within_shard_siblings,
            });
        }
        if cursor != bytes.len() {
            return Err(TreeError::InvalidSnapshot("trailing bytes".to_owned()));
        }

        Ok(Self {
            depth,
            shard_height,
            completed_roots,
            live_leaves,
            owned_notes,
        })
    }
}

fn append_fields(bytes: &mut Vec<u8>, fields: &[Fr]) {
    for field in fields {
        bytes.extend_from_slice(&fr_to_be_32(field));
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, TreeError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| TreeError::InvalidSnapshot("truncated u32".to_owned()))?
        .try_into()
        .map_err(|_| TreeError::InvalidSnapshot("invalid u32".to_owned()))?;
    Ok(u32::from_be_bytes(raw))
}

fn read_u32_at_cursor(bytes: &[u8], cursor: &mut usize) -> Result<u32, TreeError> {
    let value = read_u32(bytes, *cursor)?;
    *cursor += 4;
    Ok(value)
}

fn read_field(bytes: &[u8], cursor: &mut usize) -> Result<Fr, TreeError> {
    let raw = bytes
        .get(*cursor..*cursor + 32)
        .ok_or_else(|| TreeError::InvalidSnapshot("truncated field element".to_owned()))?;
    let field = fr_from_be_32_checked(raw)
        .ok_or_else(|| TreeError::InvalidSnapshot("non-canonical field element".to_owned()))?;
    *cursor += 32;
    Ok(field)
}

fn read_fields(bytes: &[u8], cursor: &mut usize, count: usize) -> Result<Vec<Fr>, TreeError> {
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        fields.push(read_field(bytes, cursor)?);
    }
    Ok(fields)
}

/// Stateful depth-`depth` notes tree split into fixed-height shards.
///
/// Only the rightmost shard stores leaves and internal nodes. Completed shards
/// are represented by one root each in a mutable cap tree. Owned notes retain
/// their immutable within-shard path after rollover; the current cap path is
/// attached on demand, producing a normal depth-`depth` inclusion proof.
#[derive(Clone)]
pub struct ShardedNotesTree {
    depth: usize,
    shard_height: usize,
    shard_size: usize,
    cap_depth: usize,
    completed_roots: Vec<Fr>,
    live: Imt,
    live_leaves: Vec<Fr>,
    cap: Imt,
    owned_notes: HashMap<Fr, OwnedNoteWitness>,
    dirty_owned_notes: HashSet<Fr>,
}

impl ShardedNotesTree {
    pub fn new(depth: usize, shard_height: usize) -> Result<Self, TreeError> {
        if shard_height == 0 || shard_height >= depth {
            return Err(TreeError::InvalidGeometry {
                depth,
                shard_height,
            });
        }
        let shard_size = tree_capacity(shard_height)?;
        let cap_depth = depth - shard_height;
        tree_capacity(depth)?;
        let global_zeroes = zero_roots(depth);

        Ok(Self {
            depth,
            shard_height,
            shard_size,
            cap_depth,
            completed_roots: Vec::new(),
            live: Imt::new(shard_height),
            live_leaves: Vec::new(),
            cap: Imt::new_with_zero(cap_depth, global_zeroes[shard_height]),
            owned_notes: HashMap::new(),
            dirty_owned_notes: HashSet::new(),
        })
    }

    pub fn from_snapshot(snapshot: ShardedTreeSnapshot) -> Result<Self, TreeError> {
        let mut tree = Self::new(snapshot.depth, snapshot.shard_height)?;
        let max_shards = tree_capacity(tree.cap_depth)?;
        if snapshot.completed_roots.len() > max_shards {
            return Err(TreeError::InvalidSnapshot(
                "too many completed shard roots".to_owned(),
            ));
        }
        if snapshot.live_leaves.len() >= tree.shard_size {
            return Err(TreeError::InvalidSnapshot(
                "the live shard must contain fewer than one complete shard".to_owned(),
            ));
        }
        if snapshot.completed_roots.len() == max_shards && !snapshot.live_leaves.is_empty() {
            return Err(TreeError::InvalidSnapshot(
                "live leaves exceed the tree capacity".to_owned(),
            ));
        }

        tree.completed_roots = snapshot.completed_roots;
        tree.live_leaves = snapshot.live_leaves;
        tree.live = Imt::from_leaves(tree.shard_height, &tree.live_leaves);
        tree.rebuild_cap();

        let capacity = tree_capacity(tree.depth)?;
        for owned in snapshot.owned_notes {
            if owned.leaf_index >= capacity {
                return Err(TreeError::InvalidSnapshot(format!(
                    "owned leaf {} exceeds capacity {capacity}",
                    owned.leaf_index,
                )));
            }
            if tree.owned_notes.contains_key(&owned.note_id)
                || tree
                    .owned_notes
                    .values()
                    .any(|existing| existing.leaf_index == owned.leaf_index)
            {
                return Err(TreeError::InvalidSnapshot(format!(
                    "duplicate owned note or leaf {}",
                    owned.leaf_index,
                )));
            }

            let shard_index = owned.leaf_index >> tree.shard_height;
            if shard_index < tree.completed_roots.len() {
                let siblings = owned.within_shard_siblings.as_ref().ok_or_else(|| {
                    TreeError::InvalidSnapshot(format!(
                        "owned leaf {} is completed but has no frozen path",
                        owned.leaf_index,
                    ))
                })?;
                tree.verify_frozen_path(owned.note_id, owned.leaf_index, siblings)?;
            } else {
                if owned.within_shard_siblings.is_some() {
                    return Err(TreeError::InvalidSnapshot(format!(
                        "owned leaf {} is not completed but has a frozen path",
                        owned.leaf_index,
                    )));
                }
                if owned.leaf_index < tree.leaf_count()
                    && tree.live.leaf(owned.leaf_index & (tree.shard_size - 1))
                        != Some(owned.note_id)
                {
                    return Err(TreeError::OwnedLeafMismatch {
                        leaf_index: owned.leaf_index,
                    });
                }
            }
            tree.owned_notes.insert(owned.note_id, owned);
        }

        Ok(tree)
    }

    /// Restore the public tree state before owned witnesses are adopted. This is
    /// the bulk boundary used by storage adapters that persist shard roots, live
    /// leaves, and account-scoped witnesses in separate tables.
    pub fn from_parts(
        depth: usize,
        shard_height: usize,
        completed_roots: Vec<Fr>,
        live_leaves: Vec<Fr>,
    ) -> Result<Self, TreeError> {
        Self::from_snapshot(ShardedTreeSnapshot {
            depth,
            shard_height,
            completed_roots,
            live_leaves,
            owned_notes: Vec::new(),
        })
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn shard_height(&self) -> usize {
        self.shard_height
    }

    pub fn shard_size(&self) -> usize {
        self.shard_size
    }

    pub fn leaf_count(&self) -> usize {
        self.completed_roots.len() * self.shard_size + self.live_leaves.len()
    }

    pub fn completed_shard_count(&self) -> usize {
        self.completed_roots.len()
    }

    pub fn owned_note_count(&self) -> usize {
        self.owned_notes.len()
    }

    pub fn owned_notes(&self) -> Vec<OwnedNoteWitness> {
        let mut owned_notes: Vec<OwnedNoteWitness> = self.owned_notes.values().cloned().collect();
        owned_notes.sort_by_key(|owned| owned.leaf_index);
        owned_notes
    }

    pub fn completed_roots(&self) -> &[Fr] {
        &self.completed_roots
    }

    pub fn live_leaves(&self) -> &[Fr] {
        &self.live_leaves
    }

    pub fn completed_shard_root(&self, shard_index: usize) -> Result<Fr, TreeError> {
        self.completed_roots
            .get(shard_index)
            .copied()
            .ok_or(TreeError::ShardNotCompleted { shard_index })
    }

    /// Append one note commitment, updating the live shard and cap in O(depth).
    pub fn append(&mut self, note_id: Fr) -> Result<(), TreeError> {
        self.ensure_room(1)?;
        self.validate_incoming_owned_note(self.leaf_count(), note_id)?;
        self.live.insert(note_id);
        self.live_leaves.push(note_id);
        self.sync_live_root()?;
        if self.live_leaves.len() == self.shard_size {
            self.roll_over()?;
        }
        Ok(())
    }

    /// Append a batch, bulk-building when that is cheaper than one insertion per
    /// leaf. Cap updates are coalesced to once per affected shard.
    pub fn append_many(&mut self, note_ids: &[Fr]) -> Result<(), TreeError> {
        self.ensure_room(note_ids.len())?;
        let first_index = self.leaf_count();
        for (offset, note_id) in note_ids.iter().copied().enumerate() {
            self.validate_incoming_owned_note(first_index + offset, note_id)?;
        }

        let mut remaining = note_ids;
        while !remaining.is_empty() {
            let room = self.shard_size - self.live_leaves.len();
            let take = room.min(remaining.len());
            let segment = &remaining[..take];
            let final_live_len = self.live_leaves.len() + segment.len();
            let rebuild_cost = final_live_len.saturating_sub(1);
            let incremental_cost = segment.len().saturating_mul(self.shard_height);

            self.live_leaves.extend_from_slice(segment);
            if rebuild_cost < incremental_cost {
                self.live = Imt::from_leaves(self.shard_height, &self.live_leaves);
            } else {
                for note_id in segment {
                    self.live.insert(*note_id);
                }
            }
            self.sync_live_root()?;
            if self.live_leaves.len() == self.shard_size {
                self.roll_over()?;
            }
            remaining = &remaining[take..];
        }
        Ok(())
    }

    /// Track an owned note. The note may already be in the live shard or may be
    /// marked immediately before its commitment is appended.
    pub fn mark_owned(&mut self, note_id: Fr, leaf_index: usize) -> Result<(), TreeError> {
        let capacity = tree_capacity(self.depth)?;
        if leaf_index >= capacity {
            return Err(TreeError::LeafIndexOutOfRange {
                index: leaf_index,
                leaf_count: capacity,
            });
        }
        let shard_index = leaf_index >> self.shard_height;
        if shard_index < self.completed_roots.len() {
            return Err(TreeError::NoteAlreadyCompleted { shard_index });
        }
        if let Some(existing) = self.owned_notes.get(&note_id) {
            if existing.leaf_index == leaf_index {
                return Ok(());
            }
            return Err(TreeError::DuplicateOwnedLeaf {
                leaf_index: existing.leaf_index,
            });
        }
        if self
            .owned_notes
            .values()
            .any(|owned| owned.note_id != note_id && owned.leaf_index == leaf_index)
        {
            return Err(TreeError::DuplicateOwnedLeaf { leaf_index });
        }
        if leaf_index < self.leaf_count()
            && self.live.leaf(leaf_index & (self.shard_size - 1)) != Some(note_id)
        {
            return Err(TreeError::OwnedLeafMismatch { leaf_index });
        }

        self.owned_notes.insert(
            note_id,
            OwnedNoteWitness {
                note_id,
                leaf_index,
                within_shard_siblings: None,
            },
        );
        self.dirty_owned_notes.insert(note_id);
        Ok(())
    }

    pub fn unmark_owned(&mut self, note_id: Fr) -> bool {
        self.dirty_owned_notes.remove(&note_id);
        self.owned_notes.remove(&note_id).is_some()
    }

    /// Adopt a recovered local path for an owned note in a completed shard.
    pub fn adopt_frozen_witness(
        &mut self,
        note_id: Fr,
        leaf_index: usize,
        within_shard_siblings: Vec<Fr>,
    ) -> Result<(), TreeError> {
        let shard_index = leaf_index >> self.shard_height;
        if shard_index >= self.completed_roots.len() {
            return Err(TreeError::ShardNotCompleted { shard_index });
        }
        if let Some(existing) = self.owned_notes.get(&note_id)
            && existing.leaf_index != leaf_index
        {
            return Err(TreeError::DuplicateOwnedLeaf {
                leaf_index: existing.leaf_index,
            });
        }
        if self
            .owned_notes
            .values()
            .any(|owned| owned.note_id != note_id && owned.leaf_index == leaf_index)
        {
            return Err(TreeError::DuplicateOwnedLeaf { leaf_index });
        }
        self.verify_frozen_path(note_id, leaf_index, &within_shard_siblings)?;
        self.owned_notes.insert(
            note_id,
            OwnedNoteWitness {
                note_id,
                leaf_index,
                within_shard_siblings: Some(within_shard_siblings),
            },
        );
        self.dirty_owned_notes.insert(note_id);
        Ok(())
    }

    pub fn root(&self) -> Fr {
        self.cap.root()
    }

    /// Produce a conventional full-depth proof for a tracked owned note.
    pub fn witness(&self, note_id: Fr) -> Result<InclusionProof, TreeError> {
        let owned = self
            .owned_notes
            .get(&note_id)
            .ok_or(TreeError::NoteNotMarked)?;
        let shard_index = owned.leaf_index >> self.shard_height;
        let within_index = owned.leaf_index & (self.shard_size - 1);

        let mut siblings = if let Some(frozen) = &owned.within_shard_siblings {
            frozen.clone()
        } else {
            if shard_index != self.completed_roots.len()
                || self.live.leaf(within_index) != Some(note_id)
            {
                return Err(TreeError::OwnedLeafMismatch {
                    leaf_index: owned.leaf_index,
                });
            }
            self.live.create_proof(within_index).siblings
        };

        let cap_proof = self.cap.create_proof(shard_index);
        siblings.extend(cap_proof.siblings);
        Ok(InclusionProof {
            leaf: note_id,
            index: owned.leaf_index,
            siblings,
            root: self.root(),
        })
    }

    /// Rewind within the mutable live shard. Crossing a completed-shard boundary
    /// requires restoring an earlier checkpoint because completed leaves have
    /// deliberately been discarded.
    pub fn rewind_live_to(&mut self, leaf_count: usize) -> Result<Vec<Fr>, TreeError> {
        let completed_leaf_count = self.completed_roots.len() * self.shard_size;
        if leaf_count < completed_leaf_count {
            return Err(TreeError::RewindBeforeCompleted {
                minimum: completed_leaf_count,
                requested: leaf_count,
            });
        }
        let current = self.leaf_count();
        if leaf_count > current {
            return Err(TreeError::LeafIndexOutOfRange {
                index: leaf_count,
                leaf_count: current,
            });
        }

        let removed: Vec<Fr> = self
            .owned_notes
            .values()
            .filter(|owned| owned.leaf_index >= leaf_count)
            .map(|owned| owned.note_id)
            .collect();
        for note_id in &removed {
            self.owned_notes.remove(note_id);
            self.dirty_owned_notes.remove(note_id);
        }

        self.live_leaves.truncate(leaf_count - completed_leaf_count);
        self.live = Imt::from_leaves(self.shard_height, &self.live_leaves);
        self.rebuild_cap();
        Ok(removed)
    }

    pub fn drain_dirty_owned_notes(&mut self) -> Vec<OwnedNoteWitness> {
        let mut dirty: Vec<OwnedNoteWitness> = self
            .dirty_owned_notes
            .drain()
            .filter_map(|note_id| self.owned_notes.get(&note_id).cloned())
            .collect();
        dirty.sort_by_key(|owned| owned.leaf_index);
        dirty
    }

    pub fn snapshot(&self) -> ShardedTreeSnapshot {
        ShardedTreeSnapshot {
            depth: self.depth,
            shard_height: self.shard_height,
            completed_roots: self.completed_roots.clone(),
            live_leaves: self.live_leaves.clone(),
            owned_notes: self.owned_notes(),
        }
    }

    pub fn encode_snapshot(&self) -> Result<Vec<u8>, TreeError> {
        self.snapshot().encode()
    }

    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, TreeError> {
        Self::from_snapshot(ShardedTreeSnapshot::decode(bytes)?)
    }

    fn ensure_room(&self, additional: usize) -> Result<(), TreeError> {
        let capacity = tree_capacity(self.depth)?;
        if additional > capacity.saturating_sub(self.leaf_count()) {
            return Err(TreeError::TreeFull { depth: self.depth });
        }
        Ok(())
    }

    fn validate_incoming_owned_note(
        &self,
        leaf_index: usize,
        note_id: Fr,
    ) -> Result<(), TreeError> {
        if self
            .owned_notes
            .values()
            .any(|owned| owned.leaf_index == leaf_index && owned.note_id != note_id)
        {
            return Err(TreeError::OwnedLeafMismatch { leaf_index });
        }
        Ok(())
    }

    fn sync_live_root(&mut self) -> Result<(), TreeError> {
        if self.live_leaves.is_empty() {
            return Ok(());
        }
        let shard_index = self.completed_roots.len();
        if self.cap.leaf_count() == shard_index {
            self.cap.insert(self.live.root());
        } else if self.cap.leaf_count() == shard_index + 1 {
            self.cap.update(shard_index, self.live.root())?;
        } else {
            return Err(TreeError::InvalidSnapshot(
                "cap/live shard index mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    fn roll_over(&mut self) -> Result<(), TreeError> {
        let completed_index = self.completed_roots.len();
        for owned in self.owned_notes.values_mut() {
            if (owned.leaf_index >> self.shard_height) != completed_index
                || owned.within_shard_siblings.is_some()
            {
                continue;
            }
            let within_index = owned.leaf_index & (self.shard_size - 1);
            if self.live.leaf(within_index) != Some(owned.note_id) {
                return Err(TreeError::OwnedLeafMismatch {
                    leaf_index: owned.leaf_index,
                });
            }
            owned.within_shard_siblings = Some(self.live.create_proof(within_index).siblings);
            self.dirty_owned_notes.insert(owned.note_id);
        }

        self.completed_roots.push(self.live.root());
        self.live = Imt::new(self.shard_height);
        self.live_leaves.clear();
        Ok(())
    }

    fn verify_frozen_path(
        &self,
        note_id: Fr,
        leaf_index: usize,
        siblings: &[Fr],
    ) -> Result<(), TreeError> {
        if siblings.len() != self.shard_height {
            return Err(TreeError::InvalidSiblingCount {
                expected: self.shard_height,
                actual: siblings.len(),
            });
        }
        let shard_index = leaf_index >> self.shard_height;
        let root = self
            .completed_roots
            .get(shard_index)
            .copied()
            .ok_or(TreeError::ShardNotCompleted { shard_index })?;
        let mut node = note_id;
        let mut index = leaf_index & (self.shard_size - 1);
        for sibling in siblings {
            node = if index.is_multiple_of(2) {
                poseidon(&[node, *sibling])
            } else {
                poseidon(&[*sibling, node])
            };
            index >>= 1;
        }
        if node != root {
            return Err(TreeError::WitnessRootMismatch { shard_index });
        }
        Ok(())
    }

    fn rebuild_cap(&mut self) {
        let cap_zero = zero_roots(self.depth)[self.shard_height];
        let mut roots = self.completed_roots.clone();
        if !self.live_leaves.is_empty() {
            roots.push(self.live.root());
        }
        self.cap = Imt::from_leaves_with_zero(self.cap_depth, cap_zero, &roots);
    }
}

fn tree_capacity(depth: usize) -> Result<usize, TreeError> {
    1usize
        .checked_shl(depth as u32)
        .ok_or(TreeError::CapacityOverflow { depth })
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
fn cap_levels(
    shard_roots: Vec<Fr>,
    z: &[Fr],
    shard_height: usize,
    cap_depth: usize,
) -> Vec<Vec<Fr>> {
    let mut levels = vec![shard_roots];
    for k in 0..cap_depth {
        let h = shard_height + k;
        let level = &levels[k];
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                z[h]
            };
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
    let levels = cap_levels(
        shard_roots(leaves, shard_height),
        &z,
        shard_height,
        cap_depth,
    );
    let top = &levels[cap_depth];
    if top.is_empty() { z[depth] } else { top[0] }
}

/// The full depth-`depth` inclusion proof for the leaf at `leaf_index`: the
/// within-shard siblings glued to the shared cap path - equals the flat IMT proof.
pub fn sharded_witness(
    leaves: &[Fr],
    leaf_index: usize,
    depth: usize,
    shard_height: usize,
) -> InclusionProof {
    let z = zero_roots(depth);
    let shard_size = 1usize << shard_height;
    let cap_depth = depth - shard_height;
    let shard_index = leaf_index >> shard_height;
    let within_index = leaf_index & (shard_size - 1);

    let shard_start = shard_index * shard_size;
    let shard_end = (shard_start + shard_size).min(leaves.len());
    let shard_leaves = &leaves[shard_start..shard_end];
    let mut siblings = Imt::from_leaves(shard_height, shard_leaves)
        .create_proof(within_index)
        .siblings;

    let levels = cap_levels(
        shard_roots(leaves, shard_height),
        &z,
        shard_height,
        cap_depth,
    );
    let mut idx = shard_index;
    for k in 0..cap_depth {
        let row = &levels[k];
        let sib = idx ^ 1;
        siblings.push(if sib < row.len() {
            row[sib]
        } else {
            z[shard_height + k]
        });
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
            fr_from_dec(
                "4114686047564160449611603615418567457008101555090703535405891656262658644463"
            ),
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
            assert_eq!(
                sharded_witness(&leaves, i, depth, shard_height),
                flat.create_proof(i)
            );
        }
    }

    #[test]
    fn stateful_sharded_tree_matches_flat_across_rollovers() {
        let leaves: Vec<Fr> = (1u64..=21).map(Fr::from).collect();
        let (depth, shard_height) = (8, 3);
        let owned_indices = [2usize, 9, 19];
        let mut sharded = ShardedNotesTree::new(depth, shard_height).unwrap();
        for index in owned_indices {
            sharded.mark_owned(leaves[index], index).unwrap();
        }
        sharded.append_many(&leaves).unwrap();

        let flat = Imt::from_leaves(depth, &leaves);
        assert_eq!(sharded.root(), flat.root());
        assert_eq!(sharded.completed_shard_count(), 2);
        assert_eq!(sharded.live_leaves(), &leaves[16..]);
        for index in owned_indices {
            assert_eq!(
                sharded.witness(leaves[index]).unwrap(),
                flat.create_proof(index)
            );
        }

        let snapshot = sharded.snapshot();
        assert!(snapshot.owned_notes[0].within_shard_siblings.is_some());
        assert!(snapshot.owned_notes[1].within_shard_siblings.is_some());
        assert!(snapshot.owned_notes[2].within_shard_siblings.is_none());
    }

    #[test]
    fn stateful_snapshot_roundtrip_preserves_roots_and_witnesses() {
        let leaves: Vec<Fr> = (1u64..=19).map(Fr::from).collect();
        let mut original = ShardedNotesTree::new(8, 3).unwrap();
        original.mark_owned(leaves[1], 1).unwrap();
        original.mark_owned(leaves[17], 17).unwrap();
        original.append_many(&leaves).unwrap();

        let restored = ShardedNotesTree::from_snapshot(original.snapshot()).unwrap();
        assert_eq!(restored.root(), original.root());
        assert_eq!(restored.snapshot(), original.snapshot());
        assert_eq!(
            restored.witness(leaves[1]).unwrap(),
            original.witness(leaves[1]).unwrap()
        );
        assert_eq!(
            restored.witness(leaves[17]).unwrap(),
            original.witness(leaves[17]).unwrap()
        );

        let encoded = original.encode_snapshot().unwrap();
        let decoded = ShardedNotesTree::from_snapshot_bytes(&encoded).unwrap();
        assert_eq!(decoded.snapshot(), original.snapshot());
        let mut corrupt = encoded;
        corrupt[0] ^= 1;
        assert!(matches!(
            ShardedNotesTree::from_snapshot_bytes(&corrupt),
            Err(TreeError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn recovered_frozen_witness_is_verified_before_adoption() {
        let leaves: Vec<Fr> = (1u64..=11).map(Fr::from).collect();
        let mut sharded = ShardedNotesTree::new(8, 3).unwrap();
        sharded.append_many(&leaves).unwrap();

        let local = Imt::from_leaves(3, &leaves[..8]).create_proof(3).siblings;
        sharded
            .adopt_frozen_witness(leaves[3], 3, local.clone())
            .unwrap();
        assert_eq!(
            sharded.witness(leaves[3]).unwrap(),
            Imt::from_leaves(8, &leaves).create_proof(3)
        );

        let mut bad = Imt::from_leaves(3, &leaves[..8]).create_proof(2).siblings;
        bad[0] += Fr::from(1u64);
        assert_eq!(
            sharded.adopt_frozen_witness(leaves[2], 2, bad),
            Err(TreeError::WitnessRootMismatch { shard_index: 0 }),
        );
    }

    #[test]
    fn batch_append_and_single_append_are_identical() {
        let leaves: Vec<Fr> = (1u64..=37).map(Fr::from).collect();
        let mut batch = ShardedNotesTree::new(10, 4).unwrap();
        batch.append_many(&leaves).unwrap();

        let mut single = ShardedNotesTree::new(10, 4).unwrap();
        for leaf in &leaves {
            single.append(*leaf).unwrap();
        }
        assert_eq!(batch.snapshot(), single.snapshot());
        assert_eq!(batch.root(), Imt::from_leaves(10, &leaves).root());
    }

    #[test]
    fn rewind_is_bounded_to_the_live_shard() {
        let leaves: Vec<Fr> = (1u64..=19).map(Fr::from).collect();
        let mut sharded = ShardedNotesTree::new(8, 3).unwrap();
        sharded.mark_owned(leaves[17], 17).unwrap();
        sharded.append_many(&leaves).unwrap();

        assert_eq!(sharded.rewind_live_to(16).unwrap(), vec![leaves[17]]);
        assert_eq!(sharded.root(), Imt::from_leaves(8, &leaves[..16]).root());
        assert_eq!(sharded.leaf_count(), 16);
        assert_eq!(
            sharded.rewind_live_to(15),
            Err(TreeError::RewindBeforeCompleted {
                minimum: 16,
                requested: 15
            }),
        );
    }

    #[test]
    fn imt_update_rehashes_only_the_selected_path() {
        let mut leaves: Vec<Fr> = (1u64..=11).map(Fr::from).collect();
        let mut updated = Imt::from_leaves(6, &leaves);
        leaves[7] = Fr::from(99u64);
        updated.update(7, leaves[7]).unwrap();
        assert_eq!(updated.root(), Imt::from_leaves(6, &leaves).root());
        assert_eq!(
            updated.create_proof(7),
            Imt::from_leaves(6, &leaves).create_proof(7)
        );
    }

    #[test]
    fn indexed_tree_covers_the_sdk_merkle_surface() {
        let leaves: Vec<Fr> = (1u64..=11).map(Fr::from).collect();
        let mut tree = IndexedMerkleTree::from_leaves(6, &leaves).unwrap();
        assert_eq!(tree.root(), Imt::from_leaves(6, &leaves).root());
        assert_eq!(tree.get_index(leaves[7]), Some(7));
        assert!(verify_proof(&tree.create_proof(leaves[7]).unwrap()));
        assert_eq!(tree.insert(leaves[0]), Err(TreeError::DuplicateLeaf));

        tree.insert(Fr::from(12u64)).unwrap();
        assert_eq!(tree.leaf_count(), 12);
        tree.truncate(10).unwrap();
        assert_eq!(tree.leaves(), &leaves[..10]);
        assert_eq!(tree.get_index(Fr::from(12u64)), None);
    }

    #[test]
    fn ordered_tree_accepts_duplicate_values_and_proves_by_position() {
        let leaves = [Fr::from(7u64), Fr::from(7u64), Fr::from(9u64)];
        let tree = OrderedMerkleTree::from_leaves(4, &leaves).unwrap();

        assert_eq!(tree.root(), Imt::from_leaves(4, &leaves).root());
        assert_eq!(tree.create_proof_at(0).unwrap().leaf, leaves[0]);
        assert_eq!(tree.create_proof_at(1).unwrap().leaf, leaves[1]);
        assert!(verify_proof(&tree.create_proof_at(1).unwrap()));
    }

    #[test]
    fn notes_frontier_matches_flat_tree_after_every_append() {
        let leaves: Vec<Fr> = (1u64..=64).map(Fr::from).collect();
        let mut frontier = NotesFrontier::new(6, 3).unwrap();
        assert_eq!(frontier.root(), Imt::new(6).root());

        for (index, leaf) in leaves.iter().enumerate() {
            let appended = frontier.append(*leaf).unwrap();
            assert_eq!(appended.leaf_index, index);
            assert_eq!(
                frontier.root(),
                Imt::from_leaves(6, &leaves[..=index]).root(),
                "root mismatch after leaf {index}",
            );
        }
        assert_eq!(frontier.leaf_count(), 64);
        assert_eq!(
            frontier.append(Fr::from(65u64)),
            Err(TreeError::TreeFull { depth: 6 })
        );
    }

    #[test]
    fn notes_frontier_emits_exact_completed_shard_roots() {
        let leaves: Vec<Fr> = (1u64..=21).map(Fr::from).collect();
        let mut frontier = NotesFrontier::new(8, 3).unwrap();
        let completed = frontier.append_many(&leaves).unwrap();

        assert_eq!(completed.len(), 2);
        for (shard_index, shard) in completed.iter().enumerate() {
            let start = shard_index * 8;
            assert_eq!(shard.shard_index, shard_index);
            assert_eq!(
                shard.root,
                Imt::from_leaves(3, &leaves[start..start + 8]).root()
            );
        }
        assert_eq!(frontier.root(), Imt::from_leaves(8, &leaves).root());
    }

    #[test]
    fn notes_frontier_snapshot_is_compact_and_resumes_shard_emission() {
        let leaves: Vec<Fr> = (1u64..=37).map(Fr::from).collect();
        let mut original = NotesFrontier::new(30, 14).unwrap();
        original.append_many(&leaves[..19]).unwrap();

        let snapshot = original.encode_snapshot();
        assert!(snapshot.len() <= 1_024);
        let mut restored = NotesFrontier::from_snapshot_bytes(&snapshot).unwrap();
        assert_eq!(restored, original);

        let expected = original.append_many(&leaves[19..]).unwrap();
        let actual = restored.append_many(&leaves[19..]).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(restored, original);

        let mut corrupt = snapshot;
        corrupt.push(0);
        assert!(matches!(
            NotesFrontier::from_snapshot_bytes(&corrupt),
            Err(TreeError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn notes_frontier_full_tree_snapshot_roundtrips() {
        let leaves: Vec<Fr> = (1u64..=16).map(Fr::from).collect();
        let mut frontier = NotesFrontier::new(4, 2).unwrap();
        frontier.append_many(&leaves).unwrap();
        assert_eq!(frontier.root(), Imt::from_leaves(4, &leaves).root());

        let restored = NotesFrontier::from_snapshot_bytes(&frontier.encode_snapshot()).unwrap();
        assert_eq!(restored, frontier);
        assert_eq!(restored.root(), Imt::from_leaves(4, &leaves).root());
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
            assert!(
                verify_proof(&good),
                "valid proof must be accepted (leaf {i})"
            );

            let mut bad_leaf = good.clone();
            bad_leaf.leaf += one;
            assert!(
                !verify_proof(&bad_leaf),
                "tampered leaf must be rejected (leaf {i})"
            );

            let mut bad_sib = good.clone();
            bad_sib.siblings[0] += one;
            assert!(
                !verify_proof(&bad_sib),
                "tampered sibling must be rejected (leaf {i})"
            );

            let mut bad_root = good.clone();
            bad_root.root += one;
            assert!(
                !verify_proof(&bad_root),
                "wrong root must be rejected (leaf {i})"
            );

            // Flipping the index bit selects the sibling on the wrong side; only a
            // leaf whose flipped-index neighbour happens to be its mirror could
            // collide, which does not occur for this leaf set.
            let mut bad_index = good.clone();
            bad_index.index ^= 1;
            assert!(
                !verify_proof(&bad_index),
                "wrong index must be rejected (leaf {i})"
            );
        }
    }

    #[test]
    fn cached_zero_roots_match_freshly_computed() {
        // The cache must be a pure memoisation: identical output for every
        // depth, including past the cached table where it falls through.
        for depth in 0..=MAX_CACHED_ZERO_DEPTH + 2 {
            assert_eq!(
                zero_roots(depth),
                zero_roots_from(depth, Fr::ZERO),
                "cached zero roots diverge at depth {depth}",
            );
        }
    }

    #[test]
    fn cached_zero_roots_are_prefixes_of_one_another() {
        let deep = zero_roots(MAX_CACHED_ZERO_DEPTH);
        for depth in 0..=MAX_CACHED_ZERO_DEPTH {
            assert_eq!(
                zero_roots(depth),
                deep[..=depth],
                "depth {depth} is not a prefix of the full table",
            );
        }
    }

    #[test]
    fn zero_roots_from_is_unaffected_by_the_cache() {
        // A caller-supplied leaf must never be served from the Fr::ZERO table.
        let leaf = Fr::from(7u64);
        let custom = zero_roots_from(8, leaf);
        assert_eq!(custom[0], leaf);
        assert_ne!(custom, zero_roots(8));
    }

    #[test]
    fn production_geometry_is_valid() {
        let frontier = NotesFrontier::production();
        assert_eq!(frontier.depth(), NOTES_TREE_DEPTH);
        assert_eq!(frontier.shard_height(), NOTES_SHARD_HEIGHT);
        assert_eq!(frontier.shard_size(), NOTES_SHARD_SIZE);
        assert_eq!(frontier.leaf_count(), 0);
        assert_eq!(frontier.shard_count(), 0);
        assert_eq!(
            frontier,
            NotesFrontier::new(NOTES_TREE_DEPTH, NOTES_SHARD_HEIGHT).unwrap(),
        );
    }

    #[test]
    fn shard_count_tracks_completed_shards_only() {
        let mut frontier = NotesFrontier::new(6, 3).unwrap();
        assert_eq!(frontier.shard_count(), 0);

        for index in 0..8u64 {
            frontier.append(Fr::from(index + 1)).unwrap();
            // A shard of 2^3 leaves only completes on the eighth append.
            let expected = usize::from(index == 7);
            assert_eq!(
                frontier.shard_count(),
                expected,
                "shard_count wrong after {} leaves",
                index + 1,
            );
        }

        frontier.append(Fr::from(9u64)).unwrap();
        assert_eq!(frontier.shard_count(), 1, "partial shard must not count");
        assert_eq!(frontier.shard_count(), frontier.leaf_count() >> 3);
    }

    #[test]
    fn byte_helpers_match_the_field_api() {
        let leaves: Vec<Fr> = (1u64..=9).map(Fr::from).collect();

        let mut via_field = NotesFrontier::new(6, 3).unwrap();
        let mut via_bytes = NotesFrontier::new(6, 3).unwrap();
        for leaf in &leaves {
            let expected = via_field.append(*leaf).unwrap();
            let actual = via_bytes.append_be_32(&fr_to_be_32(leaf)).unwrap();
            assert_eq!(actual, expected);
        }

        assert_eq!(via_bytes.root_be_32(), fr_to_be_32(&via_field.root()));
        assert_eq!(via_bytes, via_field);
    }

    #[test]
    fn append_be_32_rejects_non_canonical_encodings() {
        let mut frontier = NotesFrontier::new(6, 3).unwrap();
        // 0xff..ff exceeds the BN254 modulus; it must be refused rather than
        // silently reduced into the field.
        assert_eq!(
            frontier.append_be_32(&[0xff; 32]),
            Err(TreeError::NonCanonicalField),
        );
        assert_eq!(frontier.leaf_count(), 0, "rejected leaf must not be stored");
    }
}
