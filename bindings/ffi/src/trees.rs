//! Merkle and notes-tree C ABI.
//!
//! Field arrays use concatenated canonical 32-byte big-endian values, matching
//! `curvy-wasm`. Object arrays use the packed buffers documented per function.
//!
//! Mutating calls validate out-pointers before changing state or creating
//! handles, so callers can safely retry rejected calls.

use std::ffi::{c_char, c_int};

use curvy_core::field::{
    Fr, fr_from_be_32_checked, fr_from_be_32_packed, fr_to_be_32, fr_to_be_32_packed, fr_to_dec,
};
use curvy_core::imt::{
    AppendableNotesTree, InclusionProof, IndexedMerkleTree, NotesFrontier, OrderedMerkleTree,
    ShardedNotesTree, verify_proof_at_depth,
};
use curvy_core::witness::build_bound_pending_commitment_packed;

use crate::abi::{
    CurvyBytes, CurvyStatus, Failure, bytes_in, bytes_out, failed, free_status, guard,
    guard_result, invalid, null_output, set_last_error, str_vec_out,
};
use crate::registry::Registry;

static MERKLE: Registry<IndexedMerkleTree> = Registry::new();
static ORDERED: Registry<OrderedMerkleTree> = Registry::new();
static SHARDED: Registry<ShardedNotesTree> = Registry::new();
static FRONTIER: Registry<NotesFrontier> = Registry::new();
static PROOFS: Registry<InclusionProof> = Registry::new();

// Field packing

fn decode_field(bytes: &[u8], what: &str) -> Result<Fr, Failure> {
    fr_from_be_32_checked(bytes).ok_or_else(|| {
        invalid(format_args!(
            "{what} must be one canonical 32-byte big-endian field element"
        ))
    })
}

fn decode_fields(bytes: &[u8], what: &str) -> Result<Vec<Fr>, Failure> {
    fr_from_be_32_packed(bytes).map_err(|error| invalid(format_args!("{what}: {error}")))
}

/// Appends a little-endian `u32` used by JS decoders.
fn push_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

// Shared helpers

/// Maps unknown handles to [`CurvyStatus::InvalidHandle`].
fn with_handle<T, R>(
    registry: &Registry<T>,
    handle: u64,
    body: impl FnOnce(&T) -> Result<R, Failure>,
    finish: impl FnOnce(R) -> CurvyStatus,
) -> CurvyStatus {
    guard(|| match registry.with(handle, body) {
        None => {
            set_last_error(format!("unknown or freed handle {handle}"));
            CurvyStatus::InvalidHandle
        }
        Some(Ok(value)) => finish(value),
        Some(Err(failure)) => failure.report(),
    })
}

fn with_handle_mut<T, R>(
    registry: &Registry<T>,
    handle: u64,
    body: impl FnOnce(&mut T) -> Result<R, Failure>,
    finish: impl FnOnce(R) -> CurvyStatus,
) -> CurvyStatus {
    guard(|| match registry.with_mut(handle, body) {
        None => {
            set_last_error(format!("unknown or freed handle {handle}"));
            CurvyStatus::InvalidHandle
        }
        Some(Ok(value)) => finish(value),
        Some(Err(failure)) => failure.report(),
    })
}

fn handle_out(handle: u64, out: *mut u64) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    unsafe { std::ptr::write_unaligned(out, handle) };
    CurvyStatus::Ok
}

fn u32_out(value: u32, out: *mut u32) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    unsafe { std::ptr::write_unaligned(out, value) };
    CurvyStatus::Ok
}

/// Validates the out-pointer before allocating or registering a handle.
fn construct<T>(
    registry: &'static Registry<T>,
    build: impl FnOnce() -> Result<T, Failure>,
    out: *mut u64,
) -> CurvyStatus {
    guard(|| {
        if out.is_null() {
            return null_output();
        }
        match build() {
            Ok(value) => handle_out(registry.insert(value), out),
            Err(failure) => failure.report(),
        }
    })
}

// Geometry

#[unsafe(no_mangle)]
pub extern "C" fn curvy_notes_tree_depth() -> u32 {
    curvy_core::NOTES_TREE_DEPTH as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_notes_tree_version() -> u32 {
    curvy_core::NOTES_TREE_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_notes_shard_height() -> u32 {
    curvy_core::NOTES_SHARD_HEIGHT as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_notes_shard_size() -> u32 {
    curvy_core::NOTES_SHARD_SIZE as u32
}

/// Verifies a packed inclusion proof against a tree of the expected `depth`.
///
/// Writes `1` only when `siblings` holds exactly `depth` packed fields and the
/// path from `leaf` at `index` reaches `root`. A proof for another depth,
/// including a truncated proof whose `leaf` is an internal node, writes `0`.
///
/// # Safety
/// All buffer pointers must describe readable regions of the given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_verify_merkle_proof(
    depth: u32,
    leaf: *const u8,
    leaf_len: usize,
    index: u32,
    siblings: *const u8,
    siblings_len: usize,
    root: *const u8,
    root_len: usize,
    out: *mut c_int,
) -> CurvyStatus {
    guard_result(
        || {
            let leaf =
                unsafe { bytes_in(leaf, leaf_len) }.map_err(|_| invalid("invalid leaf buffer"))?;
            let siblings = unsafe { bytes_in(siblings, siblings_len) }
                .map_err(|_| invalid("invalid siblings buffer"))?;
            let root =
                unsafe { bytes_in(root, root_len) }.map_err(|_| invalid("invalid root buffer"))?;
            Ok(InclusionProof {
                leaf: decode_field(leaf, "leaf")?,
                index: index as usize,
                siblings: decode_fields(siblings, "siblings")?,
                root: decode_field(root, "root")?,
            })
        },
        |proof| {
            if out.is_null() {
                return null_output();
            }
            let valid = verify_proof_at_depth(&proof, depth as usize);
            unsafe { std::ptr::write_unaligned(out, c_int::from(valid)) };
            CurvyStatus::Ok
        },
    )
}

// Inclusion proofs

#[unsafe(no_mangle)]
pub extern "C" fn curvy_proof_free(handle: u64) -> CurvyStatus {
    guard(|| free_status(PROOFS.remove(handle)))
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_proof_index(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &PROOFS,
        handle,
        |proof| Ok(proof.index as u32),
        |value| u32_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_proof_leaf(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &PROOFS,
        handle,
        |proof| Ok(fr_to_be_32(&proof.leaf).to_vec()),
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_proof_root(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &PROOFS,
        handle,
        |proof| Ok(fr_to_be_32(&proof.root).to_vec()),
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_proof_siblings(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &PROOFS,
        handle,
        |proof| Ok(fr_to_be_32_packed(&proof.siblings)),
        |value| bytes_out(value, out),
    )
}

// Calldata-bound pending commitments

/// Appends `note_ids` as one pending batch and returns
/// `[circuitInputJson, newNotesRoot, newNoteIndex, commitment, y, x]`. A
/// refused batch is an invalid argument, anything else a failure.
fn build_bound<T: AppendableNotesTree>(
    tree: &mut T,
    batch_size: u32,
    packed_note_ids: &[u8],
) -> Result<Vec<String>, Failure> {
    let commitment =
        build_bound_pending_commitment_packed(tree, batch_size as usize, packed_note_ids).map_err(
            |error| {
                if error.is_caller_error() {
                    invalid(error)
                } else {
                    failed(error)
                }
            },
        )?;
    let mut values = vec![
        commitment.circuit_input_json(),
        fr_to_dec(&commitment.new_notes_root),
        commitment.new_note_index.to_string(),
    ];
    values.extend(commitment.binding.public_signals().iter().map(fr_to_dec));
    Ok(values)
}

// MerkleTree

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_new(depth: u32, out: *mut u64) -> CurvyStatus {
    construct(
        &MERKLE,
        || IndexedMerkleTree::new(depth as usize).map_err(failed),
        out,
    )
}

/// # Safety
/// `packed_leaves`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_merkle_from_leaves(
    depth: u32,
    packed_leaves: *const u8,
    len: usize,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &MERKLE,
        || {
            let bytes = unsafe { bytes_in(packed_leaves, len) }
                .map_err(|_| invalid("invalid leaves buffer"))?;
            IndexedMerkleTree::from_leaves(depth as usize, &decode_fields(bytes, "leaves")?)
                .map_err(failed)
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_free(handle: u64) -> CurvyStatus {
    guard(|| free_status(MERKLE.remove(handle)))
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_depth(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &MERKLE,
        handle,
        |tree| Ok(tree.depth() as u32),
        |value| u32_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_leaf_count(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &MERKLE,
        handle,
        |tree| Ok(tree.leaf_count() as u32),
        |value| u32_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_root(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &MERKLE,
        handle,
        |tree| Ok(fr_to_be_32(&tree.root()).to_vec()),
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_leaves(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &MERKLE,
        handle,
        |tree| Ok(fr_to_be_32_packed(tree.leaves())),
        |value| bytes_out(value, out),
    )
}

/// # Safety
/// `leaf`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_merkle_insert(
    handle: u64,
    leaf: *const u8,
    len: usize,
    out: *mut u32,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle_mut(
        &MERKLE,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(leaf, len) }.map_err(|_| invalid("invalid leaf buffer"))?;
            tree.insert(decode_field(bytes, "leaf")?)
                .map(|index| index as u32)
                .map_err(failed)
        },
        |value| u32_out(value, out),
    )
}

/// # Safety
/// `packed_leaves`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_merkle_insert_many(
    handle: u64,
    packed_leaves: *const u8,
    len: usize,
) -> CurvyStatus {
    with_handle_mut(
        &MERKLE,
        handle,
        |tree| {
            let bytes = unsafe { bytes_in(packed_leaves, len) }
                .map_err(|_| invalid("invalid leaves buffer"))?;
            tree.insert_many(&decode_fields(bytes, "leaves")?)
                .map_err(failed)
        },
        |()| CurvyStatus::Ok,
    )
}

/// Writes `-1` when the leaf is absent.
///
/// # Safety
/// `leaf`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_merkle_get_index(
    handle: u64,
    leaf: *const u8,
    len: usize,
    out: *mut i64,
) -> CurvyStatus {
    with_handle(
        &MERKLE,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(leaf, len) }.map_err(|_| invalid("invalid leaf buffer"))?;
            Ok(tree
                .get_index(decode_field(bytes, "leaf")?)
                .map_or(-1_i64, |index| index as i64))
        },
        |value| {
            if out.is_null() {
                return null_output();
            }
            unsafe { std::ptr::write_unaligned(out, value) };
            CurvyStatus::Ok
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_truncate(handle: u64, leaf_count: u32) -> CurvyStatus {
    with_handle_mut(
        &MERKLE,
        handle,
        |tree| tree.truncate(leaf_count as usize).map_err(failed),
        |()| CurvyStatus::Ok,
    )
}

/// Appends a pending batch and builds the calldata-bound pending-notes
/// circuit's input for it, as a JSON string array
/// `[circuitInputJson, newNotesRoot, newNoteIndex, commitment, y, x]`.
/// `circuitInputJson` is the witness input, `x` included; the other values are
/// decimal, and the last three are the proof's public signals in their order.
/// `commitPendingNotes` is sent the ids as passed here, without padding.
///
/// Nothing changes unless every id is accepted: `batch_size` between 1 and
/// 4,096, at least one id, at most `batch_size`, none zero, none repeated, none
/// already in the tree. Those refusals return `InvalidArgument`; a full tree
/// returns `Error`.
///
/// # Safety
/// `packed_note_ids`/`len` must describe a readable region of 32-byte fields.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_merkle_build_bound_pending_commitment(
    handle: u64,
    batch_size: u32,
    packed_note_ids: *const u8,
    len: usize,
    out: *mut *mut c_char,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle_mut(
        &MERKLE,
        handle,
        |tree| {
            let bytes = unsafe { bytes_in(packed_note_ids, len) }
                .map_err(|_| invalid("invalid pending note ids buffer"))?;
            build_bound(tree, batch_size, bytes)
        },
        |values| str_vec_out(values, out),
    )
}

/// The calldata-bound circuit's `frontier` input for the next batch, packed
/// bottom to top: the left-hand node where the next free leaf's path turns
/// right, zero where it turns left. Fails when the tree is full.
#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_next_leaf_frontier(
    handle: u64,
    out: *mut CurvyBytes,
) -> CurvyStatus {
    with_handle(
        &MERKLE,
        handle,
        |tree| {
            Ok(fr_to_be_32_packed(
                &tree.next_leaf_frontier().map_err(failed)?,
            ))
        },
        |value| bytes_out(value, out),
    )
}

/// # Safety
/// `leaf`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_merkle_proof(
    handle: u64,
    leaf: *const u8,
    len: usize,
    out: *mut u64,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle(
        &MERKLE,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(leaf, len) }.map_err(|_| invalid("invalid leaf buffer"))?;
            tree.create_proof(decode_field(bytes, "leaf")?)
                .map_err(failed)
        },
        |proof| handle_out(PROOFS.insert(proof), out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_proof_at(handle: u64, index: u32, out: *mut u64) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle(
        &MERKLE,
        handle,
        |tree| tree.create_proof_at(index as usize).map_err(failed),
        |proof| handle_out(PROOFS.insert(proof), out),
    )
}

// OrderedMerkleTree

#[unsafe(no_mangle)]
pub extern "C" fn curvy_ordered_new(depth: u32, out: *mut u64) -> CurvyStatus {
    construct(
        &ORDERED,
        || OrderedMerkleTree::new(depth as usize).map_err(failed),
        out,
    )
}

/// # Safety
/// `packed_leaves`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_ordered_from_leaves(
    depth: u32,
    packed_leaves: *const u8,
    len: usize,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &ORDERED,
        || {
            let bytes = unsafe { bytes_in(packed_leaves, len) }
                .map_err(|_| invalid("invalid leaves buffer"))?;
            OrderedMerkleTree::from_leaves(depth as usize, &decode_fields(bytes, "leaves")?)
                .map_err(failed)
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_ordered_free(handle: u64) -> CurvyStatus {
    guard(|| free_status(ORDERED.remove(handle)))
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_ordered_depth(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &ORDERED,
        handle,
        |tree| Ok(tree.depth() as u32),
        |value| u32_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_ordered_leaf_count(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &ORDERED,
        handle,
        |tree| Ok(tree.leaf_count() as u32),
        |value| u32_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_ordered_root(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &ORDERED,
        handle,
        |tree| Ok(fr_to_be_32(&tree.root()).to_vec()),
        |value| bytes_out(value, out),
    )
}

/// # Safety
/// `leaf`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_ordered_insert(
    handle: u64,
    leaf: *const u8,
    len: usize,
    out: *mut u32,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle_mut(
        &ORDERED,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(leaf, len) }.map_err(|_| invalid("invalid leaf buffer"))?;
            tree.insert(decode_field(bytes, "leaf")?)
                .map(|index| index as u32)
                .map_err(failed)
        },
        |value| u32_out(value, out),
    )
}

/// # Safety
/// `packed_leaves`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_ordered_insert_many(
    handle: u64,
    packed_leaves: *const u8,
    len: usize,
) -> CurvyStatus {
    with_handle_mut(
        &ORDERED,
        handle,
        |tree| {
            let bytes = unsafe { bytes_in(packed_leaves, len) }
                .map_err(|_| invalid("invalid leaves buffer"))?;
            tree.insert_many(&decode_fields(bytes, "leaves")?)
                .map_err(failed)
        },
        |()| CurvyStatus::Ok,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_ordered_proof_at(handle: u64, index: u32, out: *mut u64) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle(
        &ORDERED,
        handle,
        |tree| tree.create_proof_at(index as usize).map_err(failed),
        |proof| handle_out(PROOFS.insert(proof), out),
    )
}

// ShardedNotesTree

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_new(depth: u32, shard_height: u32, out: *mut u64) -> CurvyStatus {
    construct(
        &SHARDED,
        || ShardedNotesTree::new(depth as usize, shard_height as usize).map_err(failed),
        out,
    )
}

/// # Safety
/// `snapshot`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sharded_restore(
    snapshot: *const u8,
    len: usize,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &SHARDED,
        || {
            let bytes = unsafe { bytes_in(snapshot, len) }
                .map_err(|_| invalid("invalid snapshot buffer"))?;
            ShardedNotesTree::from_snapshot_bytes(bytes).map_err(failed)
        },
        out,
    )
}

/// # Safety
/// Both buffer pointers must describe readable regions of the given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sharded_restore_parts(
    depth: u32,
    shard_height: u32,
    completed_roots: *const u8,
    completed_roots_len: usize,
    live_leaves: *const u8,
    live_leaves_len: usize,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &SHARDED,
        || {
            let roots = unsafe { bytes_in(completed_roots, completed_roots_len) }
                .map_err(|_| invalid("invalid completed roots buffer"))?;
            let leaves = unsafe { bytes_in(live_leaves, live_leaves_len) }
                .map_err(|_| invalid("invalid live leaves buffer"))?;
            ShardedNotesTree::from_parts(
                depth as usize,
                shard_height as usize,
                decode_fields(roots, "completed shard roots")?,
                decode_fields(leaves, "live leaves")?,
            )
            .map_err(failed)
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_free(handle: u64) -> CurvyStatus {
    guard(|| free_status(SHARDED.remove(handle)))
}

// Keep these explicit because cbindgen does not expand macros.

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_depth(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |value| Ok(value.depth() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_leaf_count(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |value| Ok(value.leaf_count() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_shard_height(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |value| Ok(value.shard_height() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_shard_size(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |value| Ok(value.shard_size() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_completed_shard_count(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |value| Ok(value.completed_shard_count() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_owned_note_count(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |value| Ok(value.owned_note_count() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_root(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |tree| Ok(fr_to_be_32(&tree.root()).to_vec()),
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_snapshot(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |tree| tree.encode_snapshot().map_err(failed),
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_completed_shard_roots(
    handle: u64,
    out: *mut CurvyBytes,
) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |tree| Ok(fr_to_be_32_packed(tree.completed_roots())),
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_completed_shard_root(
    handle: u64,
    shard_index: u32,
    out: *mut CurvyBytes,
) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |tree| {
            tree.completed_shard_root(shard_index as usize)
                .map(|root| fr_to_be_32(&root).to_vec())
                .map_err(failed)
        },
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_live_leaves(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |tree| Ok(fr_to_be_32_packed(tree.live_leaves())),
        |value| bytes_out(value, out),
    )
}

/// # Safety
/// `note_id`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sharded_append(
    handle: u64,
    note_id: *const u8,
    len: usize,
) -> CurvyStatus {
    with_handle_mut(
        &SHARDED,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(note_id, len) }.map_err(|_| invalid("invalid note id buffer"))?;
            tree.append(decode_field(bytes, "note id")?).map_err(failed)
        },
        |()| CurvyStatus::Ok,
    )
}

/// # Safety
/// `packed_note_ids`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sharded_append_many(
    handle: u64,
    packed_note_ids: *const u8,
    len: usize,
) -> CurvyStatus {
    with_handle_mut(
        &SHARDED,
        handle,
        |tree| {
            let bytes = unsafe { bytes_in(packed_note_ids, len) }
                .map_err(|_| invalid("invalid note ids buffer"))?;
            tree.append_many(&decode_fields(bytes, "note ids")?)
                .map_err(failed)
        },
        |()| CurvyStatus::Ok,
    )
}

/// # Safety
/// `note_id`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sharded_mark_owned(
    handle: u64,
    note_id: *const u8,
    len: usize,
    leaf_index: u32,
) -> CurvyStatus {
    with_handle_mut(
        &SHARDED,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(note_id, len) }.map_err(|_| invalid("invalid note id buffer"))?;
            tree.mark_owned(decode_field(bytes, "note id")?, leaf_index as usize)
                .map_err(failed)
        },
        |()| CurvyStatus::Ok,
    )
}

/// # Safety
/// `note_id`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sharded_unmark_owned(
    handle: u64,
    note_id: *const u8,
    len: usize,
    out: *mut c_int,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle_mut(
        &SHARDED,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(note_id, len) }.map_err(|_| invalid("invalid note id buffer"))?;
            Ok(tree.unmark_owned(decode_field(bytes, "note id")?))
        },
        |removed| {
            if out.is_null() {
                return null_output();
            }
            unsafe { std::ptr::write_unaligned(out, c_int::from(removed)) };
            CurvyStatus::Ok
        },
    )
}

/// # Safety
/// Both buffer pointers must describe readable regions of the given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sharded_adopt_frozen_witness(
    handle: u64,
    note_id: *const u8,
    note_id_len: usize,
    leaf_index: u32,
    siblings: *const u8,
    siblings_len: usize,
) -> CurvyStatus {
    with_handle_mut(
        &SHARDED,
        handle,
        |tree| {
            let note_bytes = unsafe { bytes_in(note_id, note_id_len) }
                .map_err(|_| invalid("invalid note id buffer"))?;
            let sibling_bytes = unsafe { bytes_in(siblings, siblings_len) }
                .map_err(|_| invalid("invalid siblings buffer"))?;
            tree.adopt_frozen_witness(
                decode_field(note_bytes, "note id")?,
                leaf_index as usize,
                decode_fields(sibling_bytes, "within-shard siblings")?,
            )
            .map_err(failed)
        },
        |()| CurvyStatus::Ok,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_rewind_live_to(
    handle: u64,
    leaf_count: u32,
    out: *mut CurvyBytes,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle_mut(
        &SHARDED,
        handle,
        |tree| {
            tree.rewind_live_to(leaf_count as usize)
                .map(|removed| fr_to_be_32_packed(&removed))
                .map_err(failed)
        },
        |value| bytes_out(value, out),
    )
}

/// # Safety
/// `note_id`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sharded_witness(
    handle: u64,
    note_id: *const u8,
    len: usize,
    out: *mut u64,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle(
        &SHARDED,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(note_id, len) }.map_err(|_| invalid("invalid note id buffer"))?;
            tree.witness(decode_field(bytes, "note id")?)
                .map_err(failed)
        },
        |proof| handle_out(PROOFS.insert(proof), out),
    )
}

/// Owned-note witnesses, packed as
/// `[u32 count]` then per entry
/// `[u8 frozen][u32 leafIndex][32B noteId][u32 siblingsLen][siblings]`.
///
/// Serialised rather than handed out as handles because a drain of a few
/// thousand notes would otherwise mean a few thousand FFI round-trips.
fn pack_owned_notes(notes: &[curvy_core::imt::OwnedNoteWitness]) -> Vec<u8> {
    let mut buffer = Vec::new();
    push_u32(&mut buffer, notes.len() as u32);
    for note in notes {
        // A note is frozen once its shard captures within-shard siblings.
        buffer.push(u8::from(note.within_shard_siblings.is_some()));
        push_u32(&mut buffer, note.leaf_index as u32);
        buffer.extend_from_slice(&fr_to_be_32(&note.note_id));
        let siblings = note
            .within_shard_siblings
            .as_deref()
            .map(fr_to_be_32_packed)
            .unwrap_or_default();
        push_u32(&mut buffer, siblings.len() as u32);
        buffer.extend_from_slice(&siblings);
    }
    buffer
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_owned_notes(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |tree| Ok(pack_owned_notes(&tree.owned_notes())),
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_drain_dirty_owned_notes(
    handle: u64,
    out: *mut CurvyBytes,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle_mut(
        &SHARDED,
        handle,
        |tree| Ok(pack_owned_notes(&tree.drain_dirty_owned_notes())),
        |value| bytes_out(value, out),
    )
}

// NotesFrontier

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_new(depth: u32, shard_height: u32, out: *mut u64) -> CurvyStatus {
    construct(
        &FRONTIER,
        || NotesFrontier::new(depth as usize, shard_height as usize).map_err(failed),
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_production(out: *mut u64) -> CurvyStatus {
    construct(&FRONTIER, || Ok(NotesFrontier::production()), out)
}

/// # Safety
/// `snapshot`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_frontier_restore(
    snapshot: *const u8,
    len: usize,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &FRONTIER,
        || {
            let bytes = unsafe { bytes_in(snapshot, len) }
                .map_err(|_| invalid("invalid snapshot buffer"))?;
            NotesFrontier::from_snapshot_bytes(bytes).map_err(failed)
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_free(handle: u64) -> CurvyStatus {
    guard(|| free_status(FRONTIER.remove(handle)))
}

// Keep these explicit because cbindgen does not expand macros.

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_depth(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &FRONTIER,
        handle,
        |value| Ok(value.depth() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_leaf_count(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &FRONTIER,
        handle,
        |value| Ok(value.leaf_count() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_shard_count(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &FRONTIER,
        handle,
        |value| Ok(value.shard_count() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_shard_height(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &FRONTIER,
        handle,
        |value| Ok(value.shard_height() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_shard_size(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &FRONTIER,
        handle,
        |value| Ok(value.shard_size() as u32),
        |v| u32_out(v, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_root(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &FRONTIER,
        handle,
        |frontier| Ok(fr_to_be_32(&frontier.root()).to_vec()),
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_snapshot(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &FRONTIER,
        handle,
        |frontier| Ok(frontier.encode_snapshot()),
        |value| bytes_out(value, out),
    )
}

/// One append, packed as
/// `[u32 leafIndex][u8 hasCompletedShard][u32 shardIndex][32B shardRoot]`.
///
/// # Safety
/// `leaf`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_frontier_append(
    handle: u64,
    leaf: *const u8,
    len: usize,
    out: *mut CurvyBytes,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle_mut(
        &FRONTIER,
        handle,
        |frontier| {
            let bytes =
                unsafe { bytes_in(leaf, len) }.map_err(|_| invalid("invalid leaf buffer"))?;
            let append = frontier
                .append(decode_field(bytes, "leaf")?)
                .map_err(failed)?;
            let mut buffer = Vec::with_capacity(41);
            push_u32(&mut buffer, append.leaf_index as u32);
            match append.completed_shard {
                Some(shard) => {
                    buffer.push(1);
                    push_u32(&mut buffer, shard.shard_index as u32);
                    buffer.extend_from_slice(&fr_to_be_32(&shard.root));
                }
                None => {
                    buffer.push(0);
                    // Keep the layout fixed-width so the JS decoder's offsets
                    // don't depend on whether a shard completed.
                    push_u32(&mut buffer, 0);
                    buffer.extend_from_slice(&[0_u8; 32]);
                }
            }
            Ok(buffer)
        },
        |value| bytes_out(value, out),
    )
}

/// Bulk append; returns the completed shards as
/// `[u32 count]` then per shard `[u32 shardIndex][32B root]`.
///
/// # Safety
/// `packed_leaves`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_frontier_append_many(
    handle: u64,
    packed_leaves: *const u8,
    len: usize,
    out: *mut CurvyBytes,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle_mut(
        &FRONTIER,
        handle,
        |frontier| {
            let bytes = unsafe { bytes_in(packed_leaves, len) }
                .map_err(|_| invalid("invalid leaves buffer"))?;
            let shards = frontier
                .append_many(&decode_fields(bytes, "leaves")?)
                .map_err(failed)?;
            let mut buffer = Vec::with_capacity(4 + shards.len() * 36);
            push_u32(&mut buffer, shards.len() as u32);
            for shard in shards {
                push_u32(&mut buffer, shard.shard_index as u32);
                buffer.extend_from_slice(&fr_to_be_32(&shard.root));
            }
            Ok(buffer)
        },
        |value| bytes_out(value, out),
    )
}

/// See [`curvy_merkle_build_bound_pending_commitment`]. A frontier keeps no
/// leaves, so it cannot refuse an id that is already in the tree.
///
/// # Safety
/// `packed_note_ids`/`len` must describe a readable region of 32-byte fields.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_frontier_build_bound_pending_commitment(
    handle: u64,
    batch_size: u32,
    packed_note_ids: *const u8,
    len: usize,
    out: *mut *mut c_char,
) -> CurvyStatus {
    if out.is_null() {
        return null_output();
    }
    with_handle_mut(
        &FRONTIER,
        handle,
        |frontier| {
            let bytes = unsafe { bytes_in(packed_note_ids, len) }
                .map_err(|_| invalid("invalid pending note ids buffer"))?;
            build_bound(frontier, batch_size, bytes)
        },
        |values| str_vec_out(values, out),
    )
}

/// See [`curvy_merkle_next_leaf_frontier`].
#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_next_leaf_frontier(
    handle: u64,
    out: *mut CurvyBytes,
) -> CurvyStatus {
    with_handle(
        &FRONTIER,
        handle,
        |frontier| {
            Ok(fr_to_be_32_packed(
                &frontier.next_leaf_frontier().map_err(failed)?,
            ))
        },
        |value| bytes_out(value, out),
    )
}
