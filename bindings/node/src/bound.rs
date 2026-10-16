//! The aggregator's calldata-bound circuits: the calldata binding, and the
//! calldata-bound pending-notes commitment on both notes-tree forms. Field
//! elements cross as decimal strings, or packed in the `*Packed` calls.

use curvy_core::{
    calldata::{
        CalldataBinding as CoreCalldataBinding, CalldataError, MAX_CALLDATA_WORDS,
        bind_calldata as core_bind_calldata, bind_calldata_packed as core_bind_calldata_packed,
    },
    field::fr_to_dec,
    imt::AppendableNotesTree,
    witness::{
        BoundPendingCommitment, PendingCommitmentError, build_bound_pending_commitment,
        build_bound_pending_commitment_packed,
    },
};
use napi::{Error, Result, Status, bindgen_prelude::Buffer};
use napi_derive::napi;

use crate::{
    DECIMAL_JSON_BYTES_PER_FIELD, IndexedMerkleTree, NotesFrontier, batch_size_from_js,
    native_error, parse_fields_json, parse_pending_note_ids_json,
};

/// One pending batch as the calldata-bound pending-notes circuit and
/// `commitPendingNotes` see it. Field elements are decimal strings.
#[napi(object)]
pub struct BoundPendingCommitmentInput {
    /// `VerifyPendingNotesCommitmentBound` input, `x` included: currentNoteIndex,
    /// currentNotesRoot, pendingNoteIds (the batch padded with zeros at the end),
    /// frontier and x.
    pub circuit_input_json: String,
    /// What `commitPendingNotes` is sent: the batch without its padding.
    pub note_ids: Vec<String>,
    pub new_notes_root: String,
    pub new_note_index: u32,
    /// The proof's public signals are `[commitment, y, x]`.
    pub commitment: String,
    pub y: String,
    pub x: String,
}

/// The three values that tie a proof to its calldata words, in the order of
/// the proof's public signals, `[commitment, y, x]`. Decimal strings.
#[napi(object)]
pub struct CalldataBinding {
    pub commitment: String,
    pub y: String,
    pub x: String,
}

impl From<CoreCalldataBinding> for CalldataBinding {
    fn from(binding: CoreCalldataBinding) -> Self {
        Self {
            commitment: fr_to_dec(&binding.commitment),
            y: fr_to_dec(&binding.y),
            x: fr_to_dec(&binding.x),
        }
    }
}

/// Bind calldata words the way the aggregator's bound circuits and contract do:
/// `commitment` is the Poseidon chain over the words, `x` is
/// `keccak256(words ‖ commitment) mod r` and `y` the words evaluated at `x`.
/// `wordsJson` is a JSON array of at most 8,192 decimal strings, each below the
/// field modulus.
#[napi(js_name = "bindCalldata", catch_unwind)]
pub fn bind_calldata(words_json: String) -> Result<CalldataBinding> {
    let budget = MAX_CALLDATA_WORDS * DECIMAL_JSON_BYTES_PER_FIELD + 2;
    if words_json.len() > budget {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "calldata words JSON exceeds its {budget}-byte budget; send it without whitespace or use bindCalldataPacked"
            ),
        ));
    }
    let words = parse_fields_json(&words_json, "calldata words")?;
    core_bind_calldata(&words)
        .map(CalldataBinding::from)
        .map_err(calldata_error)
}

/// Packed counterpart to `bindCalldata`. Each word is a canonical 32-byte
/// big-endian BN254 field element.
#[napi(js_name = "bindCalldataPacked", catch_unwind)]
pub fn bind_calldata_packed(words: Buffer) -> Result<CalldataBinding> {
    core_bind_calldata_packed(&words)
        .map(CalldataBinding::from)
        .map_err(calldata_error)
}

/// Every calldata refusal is the caller's: no words, too many, or one that is
/// not a canonical field element.
fn calldata_error(error: CalldataError) -> Error {
    Error::new(Status::InvalidArg, error.to_string())
}

#[napi]
impl IndexedMerkleTree {
    /// Append the batch and return the calldata-bound pending-notes circuit's
    /// input for it. Nothing changes unless every id is accepted: `batchSize` an
    /// integer from 1 to 4096, at least one id, at most `batchSize`, none zero,
    /// none repeated, none already in the tree.
    #[napi(js_name = "buildBoundPendingCommitment", catch_unwind)]
    pub fn build_bound_pending_commitment(
        &mut self,
        batch_size: f64,
        pending_note_ids_json: String,
    ) -> Result<BoundPendingCommitmentInput> {
        build_bound(
            &mut self.tree,
            batch_size,
            NoteIds::Json(&pending_note_ids_json),
        )
    }

    /// Packed counterpart to `buildBoundPendingCommitment`. Each pending note id
    /// is a canonical 32-byte big-endian BN254 field element.
    #[napi(js_name = "buildBoundPendingCommitmentPacked", catch_unwind)]
    pub fn build_bound_pending_commitment_packed(
        &mut self,
        batch_size: f64,
        pending_note_ids: Buffer,
    ) -> Result<BoundPendingCommitmentInput> {
        build_bound(
            &mut self.tree,
            batch_size,
            NoteIds::Packed(&pending_note_ids),
        )
    }

    /// The calldata-bound circuit's `frontier` input for the next batch: the
    /// left-hand node at each level where the next free leaf's path turns right,
    /// and zero where it turns left. Decimal strings, bottom to top.
    #[napi(js_name = "nextLeafFrontier", catch_unwind)]
    pub fn next_leaf_frontier(&self) -> Result<Vec<String>> {
        next_leaf_frontier(&self.tree)
    }
}

#[napi]
impl NotesFrontier {
    /// Append the batch and return the calldata-bound pending-notes circuit's
    /// input for it. Nothing changes unless every id is accepted: `batchSize` an
    /// integer from 1 to 4096, at least one id, at most `batchSize`, none zero,
    /// none repeated. A frontier holds no leaves, so an id already in the tree
    /// goes unnoticed.
    #[napi(js_name = "buildBoundPendingCommitment", catch_unwind)]
    pub fn build_bound_pending_commitment(
        &mut self,
        batch_size: f64,
        pending_note_ids_json: String,
    ) -> Result<BoundPendingCommitmentInput> {
        build_bound(
            &mut self.frontier,
            batch_size,
            NoteIds::Json(&pending_note_ids_json),
        )
    }

    /// Packed counterpart to `buildBoundPendingCommitment`. Each pending note id
    /// is a canonical 32-byte big-endian BN254 field element.
    #[napi(js_name = "buildBoundPendingCommitmentPacked", catch_unwind)]
    pub fn build_bound_pending_commitment_packed(
        &mut self,
        batch_size: f64,
        pending_note_ids: Buffer,
    ) -> Result<BoundPendingCommitmentInput> {
        build_bound(
            &mut self.frontier,
            batch_size,
            NoteIds::Packed(&pending_note_ids),
        )
    }

    /// The calldata-bound circuit's `frontier` input for the next batch: the
    /// left-hand node at each level where the next free leaf's path turns right,
    /// and zero where it turns left. Decimal strings, bottom to top.
    #[napi(js_name = "nextLeafFrontier", catch_unwind)]
    pub fn next_leaf_frontier(&self) -> Result<Vec<String>> {
        next_leaf_frontier(&self.frontier)
    }
}

/// Pending note ids as the JSON and the packed calls receive them.
enum NoteIds<'a> {
    Json(&'a str),
    Packed(&'a [u8]),
}

/// The calldata-bound pending-notes circuit input for appending `note_ids` to
/// `tree`. Everything is checked before the tree changes: the batch size, the
/// input budget, that the new note index fits `newNoteIndex`, then the core
/// builder's own checks.
fn build_bound<T: AppendableNotesTree>(
    tree: &mut T,
    batch_size: f64,
    note_ids: NoteIds<'_>,
) -> Result<BoundPendingCommitmentInput> {
    let batch_size = batch_size_from_js(batch_size)?;
    let built = match note_ids {
        NoteIds::Json(json) => {
            let note_ids = parse_pending_note_ids_json(json, batch_size)?;
            let new_note_index = new_note_index(tree, note_ids.len())?;
            build_bound_pending_commitment(tree, batch_size, &note_ids)
                .map(|commitment| (commitment, new_note_index))
        }
        NoteIds::Packed(bytes) => {
            // A batch longer than `batch_size` is the core builder's to refuse.
            let new_note_index = new_note_index(tree, (bytes.len() / 32).min(batch_size))?;
            build_bound_pending_commitment_packed(tree, batch_size, bytes)
                .map(|commitment| (commitment, new_note_index))
        }
    };
    let (commitment, new_note_index) = built.map_err(pending_commitment_error)?;
    debug_assert_eq!(commitment.new_note_index, u64::from(new_note_index));
    Ok(output(&commitment, new_note_index))
}

/// `newNoteIndex` is a `u32`, so a batch that would carry the tree past it is
/// refused before the tree changes.
fn new_note_index<T: AppendableNotesTree>(tree: &T, note_count: usize) -> Result<u32> {
    tree.leaf_count()
        .checked_add(note_count)
        .and_then(|index| u32::try_from(index).ok())
        .ok_or_else(|| {
            Error::new(
                Status::GenericFailure,
                "the new note index would not fit a u32",
            )
        })
}

fn output(commitment: &BoundPendingCommitment, new_note_index: u32) -> BoundPendingCommitmentInput {
    BoundPendingCommitmentInput {
        circuit_input_json: commitment.circuit_input_json(),
        note_ids: commitment.note_ids().iter().map(fr_to_dec).collect(),
        new_notes_root: fr_to_dec(&commitment.new_notes_root),
        new_note_index,
        commitment: fr_to_dec(&commitment.binding.commitment),
        y: fr_to_dec(&commitment.binding.y),
        x: fr_to_dec(&commitment.binding.x),
    }
}

/// A refused batch is an invalid argument; anything else, a full tree
/// included, is a failure of the call.
fn pending_commitment_error(error: PendingCommitmentError) -> Error {
    if error.is_caller_error() {
        Error::new(Status::InvalidArg, error.to_string())
    } else {
        native_error("build the bound pending commitment", error)
    }
}

fn next_leaf_frontier<T: AppendableNotesTree>(tree: &T) -> Result<Vec<String>> {
    let frontier = tree
        .next_leaf_frontier()
        .map_err(|error| native_error("read the next leaf's frontier", error))?;
    Ok(frontier.iter().map(fr_to_dec).collect())
}
