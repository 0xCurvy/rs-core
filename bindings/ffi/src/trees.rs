//! Merkle and notes-tree C ABI.
//!
//! Field arrays use concatenated canonical 32-byte big-endian values, matching
//! `curvy-wasm`. Object arrays use the packed buffers documented per function.
//!
//! Mutating calls validate out-pointers before changing state or creating
//! handles, so callers can safely retry rejected calls.

use std::ffi::c_int;

use curvy_core::field::{Fr, fr_from_be_32_checked, fr_to_be_32};
use curvy_core::imt::{
    InclusionProof, IndexedMerkleTree, NotesFrontier, OrderedMerkleTree, ShardedNotesTree,
    verify_proof,
};

use crate::abi::{CurvyBytes, CurvyStatus, bytes_in, bytes_out, guard, set_last_error};
use crate::registry::Registry;

static MERKLE: Registry<IndexedMerkleTree> = Registry::new();
static ORDERED: Registry<OrderedMerkleTree> = Registry::new();
static SHARDED: Registry<ShardedNotesTree> = Registry::new();
static FRONTIER: Registry<NotesFrontier> = Registry::new();
static PROOFS: Registry<InclusionProof> = Registry::new();

// Field packing

fn decode_field(bytes: &[u8], what: &str) -> Result<Fr, String> {
    fr_from_be_32_checked(bytes)
        .ok_or_else(|| format!("{what} must be one canonical 32-byte big-endian field element"))
}

fn decode_fields(bytes: &[u8], what: &str) -> Result<Vec<Fr>, String> {
    if !bytes.len().is_multiple_of(32) {
        return Err(format!(
            "packed {what} length {} is not divisible by 32",
            bytes.len()
        ));
    }
    bytes
        .chunks_exact(32)
        .map(|raw| decode_field(raw, what))
        .collect()
}

fn pack_fields(fields: &[Fr]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(fields.len() * 32);
    for field in fields {
        packed.extend_from_slice(&fr_to_be_32(field));
    }
    packed
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
    body: impl FnOnce(&T) -> Result<R, String>,
    finish: impl FnOnce(R) -> CurvyStatus,
) -> CurvyStatus {
    guard(|| match registry.with(handle, body) {
        None => {
            set_last_error(format!("unknown or freed handle {handle}"));
            CurvyStatus::InvalidHandle
        }
        Some(Ok(value)) => finish(value),
        Some(Err(message)) => {
            set_last_error(message);
            CurvyStatus::Error
        }
    })
}

fn with_handle_mut<T, R>(
    registry: &Registry<T>,
    handle: u64,
    body: impl FnOnce(&mut T) -> Result<R, String>,
    finish: impl FnOnce(R) -> CurvyStatus,
) -> CurvyStatus {
    guard(|| match registry.with_mut(handle, body) {
        None => {
            set_last_error(format!("unknown or freed handle {handle}"));
            CurvyStatus::InvalidHandle
        }
        Some(Ok(value)) => finish(value),
        Some(Err(message)) => {
            set_last_error(message);
            CurvyStatus::Error
        }
    })
}

fn handle_out(handle: u64, out: *mut u64) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    unsafe { *out = handle };
    CurvyStatus::Ok
}

fn u32_out(value: u32, out: *mut u32) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    unsafe { *out = value };
    CurvyStatus::Ok
}

/// Validates the out-pointer before allocating or registering a handle.
fn construct<T>(
    registry: &'static Registry<T>,
    build: impl FnOnce() -> Result<T, String>,
    out: *mut u64,
) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    guard(|| match build() {
        Ok(value) => handle_out(registry.insert(value), out),
        Err(message) => {
            set_last_error(message);
            CurvyStatus::Error
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

/// # Safety
/// All buffer pointers must describe readable regions of the given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_verify_merkle_proof(
    leaf: *const u8,
    leaf_len: usize,
    index: u32,
    siblings: *const u8,
    siblings_len: usize,
    root: *const u8,
    root_len: usize,
    out: *mut c_int,
) -> CurvyStatus {
    guard(|| {
        let (Ok(leaf), Ok(siblings), Ok(root)) = (
            unsafe { bytes_in(leaf, leaf_len) },
            unsafe { bytes_in(siblings, siblings_len) },
            unsafe { bytes_in(root, root_len) },
        ) else {
            return CurvyStatus::InvalidArgument;
        };
        let proof = match (
            decode_field(leaf, "leaf"),
            decode_fields(siblings, "siblings"),
            decode_field(root, "root"),
        ) {
            (Ok(leaf), Ok(siblings), Ok(root)) => InclusionProof {
                leaf,
                index: index as usize,
                siblings,
                root,
            },
            (Err(message), _, _) | (_, Err(message), _) | (_, _, Err(message)) => {
                set_last_error(message);
                return CurvyStatus::Error;
            }
        };
        if out.is_null() {
            return CurvyStatus::InvalidArgument;
        }
        unsafe { *out = c_int::from(verify_proof(&proof)) };
        CurvyStatus::Ok
    })
}

// Inclusion proofs

#[unsafe(no_mangle)]
pub extern "C" fn curvy_proof_free(handle: u64) {
    PROOFS.remove(handle);
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
        |proof| Ok(pack_fields(&proof.siblings)),
        |value| bytes_out(value, out),
    )
}

// MerkleTree

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_new(depth: u32, out: *mut u64) -> CurvyStatus {
    construct(
        &MERKLE,
        || IndexedMerkleTree::new(depth as usize).map_err(|e| e.to_string()),
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
                .map_err(|_| "invalid leaves buffer".to_string())?;
            IndexedMerkleTree::from_leaves(depth as usize, &decode_fields(bytes, "leaves")?)
                .map_err(|e| e.to_string())
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_free(handle: u64) {
    MERKLE.remove(handle);
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
        |tree| Ok(pack_fields(tree.leaves())),
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
        return CurvyStatus::InvalidArgument;
    }
    with_handle_mut(
        &MERKLE,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(leaf, len) }.map_err(|_| "invalid leaf buffer".to_string())?;
            tree.insert(decode_field(bytes, "leaf")?)
                .map(|index| index as u32)
                .map_err(|e| e.to_string())
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
                .map_err(|_| "invalid leaves buffer".to_string())?;
            tree.insert_many(&decode_fields(bytes, "leaves")?)
                .map_err(|e| e.to_string())
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
                unsafe { bytes_in(leaf, len) }.map_err(|_| "invalid leaf buffer".to_string())?;
            Ok(tree
                .get_index(decode_field(bytes, "leaf")?)
                .map_or(-1_i64, |index| index as i64))
        },
        |value| {
            if out.is_null() {
                return CurvyStatus::InvalidArgument;
            }
            unsafe { *out = value };
            CurvyStatus::Ok
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_truncate(handle: u64, leaf_count: u32) -> CurvyStatus {
    with_handle_mut(
        &MERKLE,
        handle,
        |tree| {
            tree.truncate(leaf_count as usize)
                .map_err(|e| e.to_string())
        },
        |()| CurvyStatus::Ok,
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
        return CurvyStatus::InvalidArgument;
    }
    with_handle(
        &MERKLE,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(leaf, len) }.map_err(|_| "invalid leaf buffer".to_string())?;
            tree.create_proof(decode_field(bytes, "leaf")?)
                .map_err(|e| e.to_string())
        },
        |proof| handle_out(PROOFS.insert(proof), out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_merkle_proof_at(handle: u64, index: u32, out: *mut u64) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    with_handle(
        &MERKLE,
        handle,
        |tree| {
            tree.create_proof_at(index as usize)
                .map_err(|e| e.to_string())
        },
        |proof| handle_out(PROOFS.insert(proof), out),
    )
}

// OrderedMerkleTree

#[unsafe(no_mangle)]
pub extern "C" fn curvy_ordered_new(depth: u32, out: *mut u64) -> CurvyStatus {
    construct(
        &ORDERED,
        || OrderedMerkleTree::new(depth as usize).map_err(|e| e.to_string()),
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
                .map_err(|_| "invalid leaves buffer".to_string())?;
            OrderedMerkleTree::from_leaves(depth as usize, &decode_fields(bytes, "leaves")?)
                .map_err(|e| e.to_string())
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_ordered_free(handle: u64) {
    ORDERED.remove(handle);
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
        return CurvyStatus::InvalidArgument;
    }
    with_handle_mut(
        &ORDERED,
        handle,
        |tree| {
            let bytes =
                unsafe { bytes_in(leaf, len) }.map_err(|_| "invalid leaf buffer".to_string())?;
            tree.insert(decode_field(bytes, "leaf")?)
                .map(|index| index as u32)
                .map_err(|e| e.to_string())
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
                .map_err(|_| "invalid leaves buffer".to_string())?;
            tree.insert_many(&decode_fields(bytes, "leaves")?)
                .map_err(|e| e.to_string())
        },
        |()| CurvyStatus::Ok,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_ordered_proof_at(handle: u64, index: u32, out: *mut u64) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    with_handle(
        &ORDERED,
        handle,
        |tree| {
            tree.create_proof_at(index as usize)
                .map_err(|e| e.to_string())
        },
        |proof| handle_out(PROOFS.insert(proof), out),
    )
}

// ShardedNotesTree

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_new(depth: u32, shard_height: u32, out: *mut u64) -> CurvyStatus {
    construct(
        &SHARDED,
        || ShardedNotesTree::new(depth as usize, shard_height as usize).map_err(|e| e.to_string()),
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
                .map_err(|_| "invalid snapshot buffer".to_string())?;
            ShardedNotesTree::from_snapshot_bytes(bytes).map_err(|e| e.to_string())
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
                .map_err(|_| "invalid completed roots buffer".to_string())?;
            let leaves = unsafe { bytes_in(live_leaves, live_leaves_len) }
                .map_err(|_| "invalid live leaves buffer".to_string())?;
            ShardedNotesTree::from_parts(
                depth as usize,
                shard_height as usize,
                decode_fields(roots, "completed shard roots")?,
                decode_fields(leaves, "live leaves")?,
            )
            .map_err(|e| e.to_string())
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_free(handle: u64) {
    SHARDED.remove(handle);
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
        |tree| tree.encode_snapshot().map_err(|e| e.to_string()),
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
        |tree| Ok(pack_fields(tree.completed_roots())),
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
                .map_err(|e| e.to_string())
        },
        |value| bytes_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_sharded_live_leaves(handle: u64, out: *mut CurvyBytes) -> CurvyStatus {
    with_handle(
        &SHARDED,
        handle,
        |tree| Ok(pack_fields(tree.live_leaves())),
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
            let bytes = unsafe { bytes_in(note_id, len) }
                .map_err(|_| "invalid note id buffer".to_string())?;
            tree.append(decode_field(bytes, "note id")?)
                .map_err(|e| e.to_string())
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
                .map_err(|_| "invalid note ids buffer".to_string())?;
            tree.append_many(&decode_fields(bytes, "note ids")?)
                .map_err(|e| e.to_string())
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
            let bytes = unsafe { bytes_in(note_id, len) }
                .map_err(|_| "invalid note id buffer".to_string())?;
            tree.mark_owned(decode_field(bytes, "note id")?, leaf_index as usize)
                .map_err(|e| e.to_string())
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
        return CurvyStatus::InvalidArgument;
    }
    with_handle_mut(
        &SHARDED,
        handle,
        |tree| {
            let bytes = unsafe { bytes_in(note_id, len) }
                .map_err(|_| "invalid note id buffer".to_string())?;
            Ok(tree.unmark_owned(decode_field(bytes, "note id")?))
        },
        |removed| {
            if out.is_null() {
                return CurvyStatus::InvalidArgument;
            }
            unsafe { *out = c_int::from(removed) };
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
                .map_err(|_| "invalid note id buffer".to_string())?;
            let sibling_bytes = unsafe { bytes_in(siblings, siblings_len) }
                .map_err(|_| "invalid siblings buffer".to_string())?;
            tree.adopt_frozen_witness(
                decode_field(note_bytes, "note id")?,
                leaf_index as usize,
                decode_fields(sibling_bytes, "within-shard siblings")?,
            )
            .map_err(|e| e.to_string())
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
        return CurvyStatus::InvalidArgument;
    }
    with_handle_mut(
        &SHARDED,
        handle,
        |tree| {
            tree.rewind_live_to(leaf_count as usize)
                .map(|removed| pack_fields(&removed))
                .map_err(|e| e.to_string())
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
        return CurvyStatus::InvalidArgument;
    }
    with_handle(
        &SHARDED,
        handle,
        |tree| {
            let bytes = unsafe { bytes_in(note_id, len) }
                .map_err(|_| "invalid note id buffer".to_string())?;
            tree.witness(decode_field(bytes, "note id")?)
                .map_err(|e| e.to_string())
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
            .map(pack_fields)
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
        return CurvyStatus::InvalidArgument;
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
        || NotesFrontier::new(depth as usize, shard_height as usize).map_err(|e| e.to_string()),
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
                .map_err(|_| "invalid snapshot buffer".to_string())?;
            NotesFrontier::from_snapshot_bytes(bytes).map_err(|e| e.to_string())
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_frontier_free(handle: u64) {
    FRONTIER.remove(handle);
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
        return CurvyStatus::InvalidArgument;
    }
    with_handle_mut(
        &FRONTIER,
        handle,
        |frontier| {
            let bytes =
                unsafe { bytes_in(leaf, len) }.map_err(|_| "invalid leaf buffer".to_string())?;
            let append = frontier
                .append(decode_field(bytes, "leaf")?)
                .map_err(|e| e.to_string())?;
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
        return CurvyStatus::InvalidArgument;
    }
    with_handle_mut(
        &FRONTIER,
        handle,
        |frontier| {
            let bytes = unsafe { bytes_in(packed_leaves, len) }
                .map_err(|_| "invalid leaves buffer".to_string())?;
            let shards = frontier
                .append_many(&decode_fields(bytes, "leaves")?)
                .map_err(|e| e.to_string())?;
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
