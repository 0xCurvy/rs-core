//! Pending-notes commitment, calldata-bound.
//!
//! The circuit appends the batch to the notes tree in one pass from the tree's
//! frontier, instead of opening a path per note, and is bound to the words
//! `commitPendingNotes` hashes,
//! `[pendingNoteIds..., currentRoot, newRoot, currentIndex, newIndex]`,
//! through [`crate::calldata`] rather than a SHA-256 input hash. The contract is
//! sent only the real note ids; the padding zeros at the end of the batch are
//! part of the words but never posted.

use ark_ff::AdditiveGroup;
use serde::Serialize;

use super::MAX_PENDING_BATCH_SIZE;
use crate::calldata::{CalldataBinding, CalldataError, MAX_CALLDATA_WORDS, bind_calldata};
use crate::field::{Fr, PackedFieldsError, fr_from_be_32_packed, fr_to_dec};
use crate::imt::{AppendableNotesTree, TreeError};

// The words are the padded batch and four tree values, so a batch the builder
// accepts always binds.
const _: () = assert!(MAX_PENDING_BATCH_SIZE + 4 <= MAX_CALLDATA_WORDS);

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PendingCommitmentError {
    /// The circuit's batch size must be between 1 and [`MAX_PENDING_BATCH_SIZE`].
    InvalidBatchSize {
        batch_size: usize,
    },
    /// A commit needs at least one note.
    NoNotes,
    /// More notes than the circuit's batch holds.
    BatchTooLarge {
        count: usize,
        batch_size: usize,
    },
    /// Zero is the padding at the end of the batch, never a note.
    ZeroNoteId,
    /// The same note twice in one batch.
    DuplicateNoteId,
    /// Packed note ids that are not canonical 32-byte field elements.
    PackedNoteIds(PackedFieldsError),
    Tree(TreeError),
    Binding(CalldataError),
}

impl PendingCommitmentError {
    /// Whether the request itself is wrong: a batch size out of range, or note
    /// ids that are missing, too many, zero, repeated, malformed or already in
    /// the tree. The bindings report these as invalid arguments, and anything
    /// else, a full tree included, as a failure of the call.
    pub fn is_caller_error(&self) -> bool {
        match self {
            Self::InvalidBatchSize { .. }
            | Self::NoNotes
            | Self::BatchTooLarge { .. }
            | Self::ZeroNoteId
            | Self::DuplicateNoteId
            | Self::PackedNoteIds(_)
            | Self::Tree(TreeError::DuplicateLeaf) => true,
            Self::Tree(_) | Self::Binding(_) => false,
        }
    }
}

impl std::fmt::Display for PendingCommitmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBatchSize { batch_size } => write!(
                f,
                "batch size must be between 1 and {MAX_PENDING_BATCH_SIZE}; got {batch_size}"
            ),
            Self::NoNotes => f.write_str("pending note ids must not be empty"),
            Self::BatchTooLarge { count, batch_size } => {
                write!(
                    f,
                    "pending note id count {count} exceeds batch size {batch_size}"
                )
            }
            Self::ZeroNoteId => f.write_str("zero is padding, not a pending note id"),
            Self::DuplicateNoteId => f.write_str("a pending note id repeats within the batch"),
            Self::PackedNoteIds(error) => write!(f, "pending note ids: {error}"),
            Self::Tree(error) => write!(f, "{error}"),
            Self::Binding(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PendingCommitmentError {}

impl From<TreeError> for PendingCommitmentError {
    fn from(error: TreeError) -> Self {
        Self::Tree(error)
    }
}

impl From<CalldataError> for PendingCommitmentError {
    fn from(error: CalldataError) -> Self {
        Self::Binding(error)
    }
}

/// One pending batch as the calldata-bound circuit and `commitPendingNotes` see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundPendingCommitment {
    pub current_note_index: u64,
    pub current_notes_root: Fr,
    /// The batch, padded with zeros at the end to the circuit's batch size.
    pub pending_note_ids: Vec<Fr>,
    /// [`AppendableNotesTree::next_leaf_frontier`] before the batch.
    pub frontier: Vec<Fr>,
    pub new_notes_root: Fr,
    pub new_note_index: u64,
    /// The proof's public signals are `[commitment, y, x]`; `x` is its input.
    pub binding: CalldataBinding,
}

impl BoundPendingCommitment {
    /// What `commitPendingNotes` is sent: the batch without its padding.
    pub fn note_ids(&self) -> &[Fr] {
        &self.pending_note_ids[..(self.new_note_index - self.current_note_index) as usize]
    }

    /// The words the proof is bound to,
    /// `[pendingNoteIds..., currentRoot, newRoot, currentIndex, newIndex]`.
    pub fn words(&self) -> Vec<Fr> {
        bound_pending_commitment_words(
            &self.pending_note_ids,
            self.current_notes_root,
            self.new_notes_root,
            self.current_note_index,
            self.new_note_index,
        )
    }

    /// [`Self::circuit_input`] as the JSON a prover takes.
    pub fn circuit_input_json(&self) -> String {
        serde_json::to_string(&self.circuit_input()).expect("a struct of strings always serializes")
    }

    /// The circuit input, `x` included, in flat snarkjs field order.
    pub fn circuit_input(&self) -> BoundPendingCommitmentInput {
        BoundPendingCommitmentInput {
            current_note_index: self.current_note_index.to_string(),
            current_notes_root: fr_to_dec(&self.current_notes_root),
            pending_note_ids: self.pending_note_ids.iter().map(fr_to_dec).collect(),
            frontier: self.frontier.iter().map(fr_to_dec).collect(),
            x: fr_to_dec(&self.binding.x),
        }
    }
}

/// `VerifyPendingNotesCommitmentBound(batchSize, treeDepth)`'s input.
#[derive(Serialize, PartialEq, Eq, Debug)]
pub struct BoundPendingCommitmentInput {
    #[serde(rename = "currentNoteIndex")]
    pub current_note_index: String,
    #[serde(rename = "currentNotesRoot")]
    pub current_notes_root: String,
    #[serde(rename = "pendingNoteIds")]
    pub pending_note_ids: Vec<String>,
    pub frontier: Vec<String>,
    pub x: String,
}

fn bound_pending_commitment_words(
    pending_note_ids: &[Fr],
    current_notes_root: Fr,
    new_notes_root: Fr,
    current_note_index: u64,
    new_note_index: u64,
) -> Vec<Fr> {
    let mut words = Vec::with_capacity(pending_note_ids.len() + 4);
    words.extend_from_slice(pending_note_ids);
    words.push(current_notes_root);
    words.push(new_notes_root);
    words.push(Fr::from(current_note_index));
    words.push(Fr::from(new_note_index));
    words
}

fn check_batch_size(batch_size: usize) -> Result<(), PendingCommitmentError> {
    if (1..=MAX_PENDING_BATCH_SIZE).contains(&batch_size) {
        Ok(())
    } else {
        Err(PendingCommitmentError::InvalidBatchSize { batch_size })
    }
}

/// Append `note_ids` to `tree` and build the calldata-bound circuit's input for
/// it, `x` and the commitment included.
///
/// Everything that can fail is checked before `tree` changes: the batch size
/// (1 to [`MAX_PENDING_BATCH_SIZE`]), the ids (at least one, at most
/// `batch_size`, none zero, none repeated), the tree's capacity and, for an
/// [`IndexedMerkleTree`](crate::imt::IndexedMerkleTree), ids it already holds. A
/// [`NotesFrontier`](crate::imt::NotesFrontier) holds no leaves, so it can refuse
/// only a repeat inside the batch.
pub fn build_bound_pending_commitment<T: AppendableNotesTree>(
    tree: &mut T,
    batch_size: usize,
    note_ids: &[Fr],
) -> Result<BoundPendingCommitment, PendingCommitmentError> {
    check_batch_size(batch_size)?;
    if note_ids.is_empty() {
        return Err(PendingCommitmentError::NoNotes);
    }
    if note_ids.len() > batch_size {
        return Err(PendingCommitmentError::BatchTooLarge {
            count: note_ids.len(),
            batch_size,
        });
    }
    if note_ids.contains(&Fr::ZERO) {
        return Err(PendingCommitmentError::ZeroNoteId);
    }
    let mut seen = std::collections::HashSet::with_capacity(note_ids.len());
    if !note_ids.iter().all(|note_id| seen.insert(*note_id)) {
        return Err(PendingCommitmentError::DuplicateNoteId);
    }
    let mut pending_note_ids = Vec::with_capacity(batch_size);
    pending_note_ids.extend_from_slice(note_ids);
    pending_note_ids.resize(batch_size, Fr::ZERO);

    let current_notes_root = tree.root();
    let current_note_index = tree.leaf_count() as u64;
    let frontier = tree.next_leaf_frontier()?;
    // Checks capacity, and for an indexed tree the ids it holds, before it
    // changes anything. Nothing after it can fail: the words always bind (see
    // the assertion at the top of this module).
    tree.append_all(note_ids)?;
    let new_notes_root = tree.root();
    let new_note_index = tree.leaf_count() as u64;

    let binding = bind_calldata(&bound_pending_commitment_words(
        &pending_note_ids,
        current_notes_root,
        new_notes_root,
        current_note_index,
        new_note_index,
    ))?;

    Ok(BoundPendingCommitment {
        current_note_index,
        current_notes_root,
        pending_note_ids,
        frontier,
        new_notes_root,
        new_note_index,
        binding,
    })
}

/// [`build_bound_pending_commitment`] over note ids packed as canonical 32-byte
/// big-endian values, as the bindings pass them. The batch size and the byte
/// length are checked before anything is decoded, and an id at or above the
/// field modulus is refused.
pub fn build_bound_pending_commitment_packed<T: AppendableNotesTree>(
    tree: &mut T,
    batch_size: usize,
    packed_note_ids: &[u8],
) -> Result<BoundPendingCommitment, PendingCommitmentError> {
    check_batch_size(batch_size)?;
    if packed_note_ids.len() > batch_size * 32 {
        return Err(PendingCommitmentError::BatchTooLarge {
            count: packed_note_ids.len().div_ceil(32),
            batch_size,
        });
    }
    let note_ids =
        fr_from_be_32_packed(packed_note_ids).map_err(PendingCommitmentError::PackedNoteIds)?;
    build_bound_pending_commitment(tree, batch_size, &note_ids)
}
