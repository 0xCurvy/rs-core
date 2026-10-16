//! The aggregator's calldata-bound circuits: the calldata binding, and the
//! calldata-bound pending-notes commitment on both notes-tree forms.
//!
//! `bindCalldata` is a scalar call and speaks decimal strings. The pending
//! commitment belongs to the trees, which take and return packed canonical
//! 32-byte fields, so every field it returns is packed; only the circuit input
//! is JSON of decimal strings, the form a prover takes.

use curvy_core::calldata::{
    CalldataBinding, CalldataError, MAX_CALLDATA_WORDS, bind_calldata as core_bind_calldata,
};
use curvy_core::field::{Bn254Fr, Fr, fr_to_be_32, fr_to_be_32_packed, fr_to_dec};
use curvy_core::imt::AppendableNotesTree;
use curvy_core::witness::{
    BoundPendingCommitment, MAX_PENDING_BATCH_SIZE, build_bound_pending_commitment_packed,
};
use wasm_bindgen::prelude::*;

use crate::{WasmMerkleTree, WasmNotesFrontier, js_tree_error};

/// Bind calldata words the way the aggregator's bound circuits and contract do.
/// `words` are decimal field elements below the modulus, at most 8,192; the
/// proof's public signals are `[commitment, y, x]`.
#[wasm_bindgen(js_name = bindCalldata)]
pub fn bind_calldata(words: Vec<String>) -> Result<WasmCalldataBinding, JsError> {
    if words.len() > MAX_CALLDATA_WORDS {
        return Err(JsError::new(
            &CalldataError::TooManyWords { count: words.len() }.to_string(),
        ));
    }
    let words = words
        .iter()
        .map(|word| canonical_field_input(word))
        .collect::<Result<Vec<_>, _>>()?;
    core_bind_calldata(&words)
        .map(WasmCalldataBinding)
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Calldata words must already be field elements: a word and that word plus the
/// modulus are one value to the proof but two to the contract.
fn canonical_field_input(s: &str) -> Result<Fr, JsError> {
    Bn254Fr::try_from_dec(s)
        .map(Bn254Fr::into_inner)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// `commitment`, `y` and `x`, the proof's public signals in their order, as
/// decimal strings.
#[wasm_bindgen(js_name = CalldataBinding)]
pub struct WasmCalldataBinding(CalldataBinding);

#[wasm_bindgen(js_class = CalldataBinding)]
impl WasmCalldataBinding {
    #[wasm_bindgen(getter)]
    pub fn commitment(&self) -> String {
        fr_to_dec(&self.0.commitment)
    }

    #[wasm_bindgen(getter)]
    pub fn y(&self) -> String {
        fr_to_dec(&self.0.y)
    }

    #[wasm_bindgen(getter)]
    pub fn x(&self) -> String {
        fr_to_dec(&self.0.x)
    }
}

/// One pending batch as the calldata-bound pending-notes circuit and
/// `commitPendingNotes` see it. Fields are packed canonical 32-byte values,
/// like every other notes-tree output.
#[wasm_bindgen(js_name = BoundPendingCommitment)]
pub struct WasmBoundPendingCommitment {
    commitment: BoundPendingCommitment,
    new_note_index: u32,
}

#[wasm_bindgen(js_class = BoundPendingCommitment)]
impl WasmBoundPendingCommitment {
    /// The circuit input, `x` included, as JSON of decimal strings.
    #[wasm_bindgen(getter, js_name = circuitInputJson)]
    pub fn circuit_input_json(&self) -> String {
        self.commitment.circuit_input_json()
    }

    /// What `commitPendingNotes` is sent: the batch without its padding.
    #[wasm_bindgen(getter, js_name = noteIds)]
    pub fn note_ids(&self) -> Vec<u8> {
        fr_to_be_32_packed(self.commitment.note_ids())
    }

    #[wasm_bindgen(getter, js_name = newNotesRoot)]
    pub fn new_notes_root(&self) -> Vec<u8> {
        fr_to_be_32(&self.commitment.new_notes_root).to_vec()
    }

    #[wasm_bindgen(getter, js_name = newNoteIndex)]
    pub fn new_note_index(&self) -> u32 {
        self.new_note_index
    }

    /// The first of the proof's public signals, `[commitment, y, x]`.
    #[wasm_bindgen(getter)]
    pub fn commitment(&self) -> Vec<u8> {
        fr_to_be_32(&self.commitment.binding.commitment).to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn y(&self) -> Vec<u8> {
        fr_to_be_32(&self.commitment.binding.y).to_vec()
    }

    /// The circuit's one public input.
    #[wasm_bindgen(getter)]
    pub fn x(&self) -> Vec<u8> {
        fr_to_be_32(&self.commitment.binding.x).to_vec()
    }
}

/// A JavaScript number is a batch size only as an integer from 1 to
/// `MAX_PENDING_BATCH_SIZE`. The `u32` conversion would wrap `2 ** 32 + 4` and
/// truncate `4.9`, both to 4.
fn batch_size_from_js(value: f64) -> Result<usize, JsError> {
    if value.fract() == 0.0 && (1.0..=MAX_PENDING_BATCH_SIZE as f64).contains(&value) {
        Ok(value as usize)
    } else {
        Err(JsError::new(&format!(
            "batchSize must be an integer between 1 and {MAX_PENDING_BATCH_SIZE}"
        )))
    }
}

/// Every check runs before the tree changes: the batch size, that the new note
/// index fits `newNoteIndex`, and then the core builder's own. Refusals and
/// failures alike throw an `Error`, as every other call here does.
fn build_bound<T: AppendableNotesTree>(
    tree: &mut T,
    batch_size: f64,
    packed_note_ids: &[u8],
) -> Result<WasmBoundPendingCommitment, JsError> {
    let batch_size = batch_size_from_js(batch_size)?;
    // A batch longer than `batch_size` is the core builder's to refuse.
    let note_count = (packed_note_ids.len() / 32).min(batch_size);
    let new_note_index = tree
        .leaf_count()
        .checked_add(note_count)
        .and_then(|index| u32::try_from(index).ok())
        .ok_or_else(|| JsError::new("the new note index would not fit a u32"))?;
    let commitment = build_bound_pending_commitment_packed(tree, batch_size, packed_note_ids)
        .map_err(|error| JsError::new(&error.to_string()))?;
    debug_assert_eq!(commitment.new_note_index, u64::from(new_note_index));
    Ok(WasmBoundPendingCommitment {
        commitment,
        new_note_index,
    })
}

#[wasm_bindgen(js_class = MerkleTree)]
impl WasmMerkleTree {
    /// Append a pending batch and build the calldata-bound circuit's input for
    /// it. Nothing changes unless every id is accepted: `batchSize` an integer
    /// from 1 to 4096, at least one id, at most `batchSize`, none zero, none
    /// repeated, none already in the tree.
    #[wasm_bindgen(js_name = buildBoundPendingCommitment)]
    pub fn build_bound_pending_commitment(
        &mut self,
        batch_size: f64,
        packed_note_ids: &[u8],
    ) -> Result<WasmBoundPendingCommitment, JsError> {
        build_bound(&mut self.inner, batch_size, packed_note_ids)
    }

    /// The calldata-bound circuit's `frontier` input for the next batch, packed
    /// bottom to top: the left-hand node where the next free leaf's path turns
    /// right, zero where it turns left.
    #[wasm_bindgen(js_name = nextLeafFrontier)]
    pub fn next_leaf_frontier(&self) -> Result<Vec<u8>, JsError> {
        Ok(fr_to_be_32_packed(
            &self.inner.next_leaf_frontier().map_err(js_tree_error)?,
        ))
    }
}

#[wasm_bindgen(js_class = NotesFrontier)]
impl WasmNotesFrontier {
    /// Append a pending batch and build the calldata-bound circuit's input for
    /// it. Nothing changes unless every id is accepted: `batchSize` an integer
    /// from 1 to 4096, at least one id, at most `batchSize`, none zero, none
    /// repeated. A frontier holds no leaves, so an id already in the tree goes
    /// unnoticed.
    #[wasm_bindgen(js_name = buildBoundPendingCommitment)]
    pub fn build_bound_pending_commitment(
        &mut self,
        batch_size: f64,
        packed_note_ids: &[u8],
    ) -> Result<WasmBoundPendingCommitment, JsError> {
        build_bound(&mut self.inner, batch_size, packed_note_ids)
    }

    /// See `MerkleTree.nextLeafFrontier`.
    #[wasm_bindgen(js_name = nextLeafFrontier)]
    pub fn next_leaf_frontier(&self) -> Result<Vec<u8>, JsError> {
        Ok(fr_to_be_32_packed(
            &self.inner.next_leaf_frontier().map_err(js_tree_error)?,
        ))
    }
}
