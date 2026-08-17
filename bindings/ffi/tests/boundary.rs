use std::ffi::{CStr, CString, c_char};

use curvy_ffi::{
    CurvyBytes, CurvyStatus, curvy_bytes_free, curvy_last_error, curvy_merkle_free,
    curvy_merkle_leaves, curvy_merkle_new, curvy_pub_from_private_key, curvy_sharded_append_many,
    curvy_sharded_drain_dirty_owned_notes, curvy_sharded_free, curvy_sharded_mark_owned,
    curvy_sharded_new, curvy_sharded_owned_note_count, curvy_string_free, curvy_witness_graph_new,
};
use curvy_witness::Limits;
use curvy_witness::wire::{FIELD_BN254_FR, FORMAT_VERSION_V1, HEADER_SIZE, MAGIC};
use sha2::{Digest, Sha256};

fn last_error() -> String {
    let pointer = curvy_last_error();
    assert!(!pointer.is_null());
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

#[test]
fn prefixed_private_key_is_an_error_not_a_panic() {
    let key = CString::new("0xab").unwrap();
    let mut out: *mut c_char = std::ptr::null_mut();
    let status = unsafe { curvy_pub_from_private_key(key.as_ptr(), &mut out) };
    assert_eq!(status, CurvyStatus::InvalidArgument);
    assert!(out.is_null());
    assert!(last_error().contains("remove the leading 0x"));
}

#[test]
fn handles_are_not_reused_after_free() {
    let mut first = 0;
    assert_eq!(curvy_merkle_new(8, &mut first), CurvyStatus::Ok);
    curvy_merkle_free(first);

    let mut second = 0;
    assert_eq!(curvy_merkle_new(8, &mut second), CurvyStatus::Ok);
    assert!(second > first);
    curvy_merkle_free(second);
}

/// A 64-byte SIGNET v1 header with no body, declaring `nodes` nodes.
fn graph_header(nodes: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_SIZE as usize);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&FORMAT_VERSION_V1.to_le_bytes());
    header.extend_from_slice(&FIELD_BN254_FR.to_le_bytes());
    header.extend_from_slice(&HEADER_SIZE.to_le_bytes());
    header.extend_from_slice(&[7_u8; 32]);
    header.extend_from_slice(&nodes.to_le_bytes());
    header.extend_from_slice(&2_u32.to_le_bytes());
    header.extend_from_slice(&1_u32.to_le_bytes());
    header.extend_from_slice(&2_u32.to_le_bytes());
    assert_eq!(header.len(), HEADER_SIZE as usize);
    header
}

fn sha256_hex(bytes: &[u8]) -> CString {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    CString::new(hex).unwrap()
}

/// Confirms batch mode uses wider graph limits than client mode.
#[test]
fn batch_profile_selects_the_wider_limit_budget() {
    let over_client = u32::try_from(Limits::client().nodes + 1).expect("fits u32");
    assert!(
        (over_client as usize) <= Limits::batch_prover().nodes,
        "the stub must be over the client budget but within the batch budget"
    );
    let header = graph_header(over_client);
    let sha = sha256_hex(&header);

    let mut handle = 0_u64;
    let status = unsafe {
        curvy_witness_graph_new(
            header.as_ptr(),
            header.len(),
            sha.as_ptr(),
            false,
            &mut handle,
        )
    };
    assert_eq!(status, CurvyStatus::Error);
    let client_error = last_error();

    let status = unsafe {
        curvy_witness_graph_new(
            header.as_ptr(),
            header.len(),
            sha.as_ptr(),
            true,
            &mut handle,
        )
    };
    assert_eq!(status, CurvyStatus::Error);
    let batch_error = last_error();

    assert_ne!(
        client_error, batch_error,
        "batch_profile was ignored: both budgets produced {client_error}"
    );
    assert!(
        client_error.contains(&Limits::client().nodes.to_string()),
        "client budget should report its own node maximum, got: {client_error}"
    );
    assert!(
        !batch_error.contains(&Limits::client().nodes.to_string()),
        "batch budget should not be capped at the client maximum, got: {batch_error}"
    );
}

#[test]
fn rust_owned_strings_use_the_matching_free_function() {
    let key =
        CString::new("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
    let mut out: *mut c_char = std::ptr::null_mut();
    assert_eq!(
        unsafe { curvy_pub_from_private_key(key.as_ptr(), &mut out) },
        CurvyStatus::Ok
    );
    assert!(!out.is_null());
    unsafe { curvy_string_free(out) };
}

/// Exercises the boxed-slice allocate/free pair with a non-power-of-two buffer.
#[test]
fn owned_buffers_free_with_the_layout_they_were_allocated_with() {
    let mut tree = 0_u64;
    assert_eq!(curvy_merkle_new(8, &mut tree), CurvyStatus::Ok);

    // Use a non-power-of-two size to exercise the exact allocation layout.
    let leaves: Vec<u8> = (1_u64..=5).flat_map(field_bytes).collect();
    let mut appended = 0_u32;
    for leaf in leaves.chunks_exact(32) {
        assert_eq!(
            unsafe {
                curvy_ffi::curvy_merkle_insert(tree, leaf.as_ptr(), leaf.len(), &mut appended)
            },
            CurvyStatus::Ok
        );
    }

    for _ in 0..64 {
        let mut out = CurvyBytes {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        assert_eq!(curvy_merkle_leaves(tree, &mut out), CurvyStatus::Ok);
        assert_eq!(out.len, 5 * 32);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(out.ptr, out.len) },
            leaves.as_slice()
        );
        unsafe { curvy_bytes_free(out) };
    }

    curvy_merkle_free(tree);
}

/// A rejected drain must leave the dirty set unchanged.
#[test]
fn a_null_out_pointer_does_not_consume_the_dirty_set() {
    let mut tree = 0_u64;
    assert_eq!(curvy_sharded_new(10, 2, &mut tree), CurvyStatus::Ok);

    let note = field_bytes(1);
    assert_eq!(
        unsafe { curvy_sharded_append_many(tree, note.as_ptr(), note.len()) },
        CurvyStatus::Ok
    );
    assert_eq!(
        unsafe { curvy_sharded_mark_owned(tree, note.as_ptr(), note.len(), 0) },
        CurvyStatus::Ok
    );

    let mut owned = 0_u32;
    assert_eq!(
        curvy_sharded_owned_note_count(tree, &mut owned),
        CurvyStatus::Ok
    );
    assert_eq!(owned, 1);

    // Rejection must not mutate state.
    assert_eq!(
        curvy_sharded_drain_dirty_owned_notes(tree, std::ptr::null_mut()),
        CurvyStatus::InvalidArgument
    );

    // The next valid drain must return the note.
    let mut out = CurvyBytes {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    assert_eq!(
        curvy_sharded_drain_dirty_owned_notes(tree, &mut out),
        CurvyStatus::Ok
    );
    let drained = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
    assert_eq!(
        u32::from_le_bytes(drained[..4].try_into().unwrap()),
        1,
        "the null-pointer call must not have consumed the dirty set"
    );
    unsafe { curvy_bytes_free(out) };

    curvy_sharded_free(tree);
}

/// Rejected constructors must not allocate unreachable handles.
///
/// The registry is shared across parallel tests, so allow small counter movement.
#[test]
fn a_null_out_pointer_does_not_strand_a_handle() {
    const REJECTED: u64 = 1_000;
    const CONCURRENT_NOISE: u64 = 100;

    let mut before = 0_u64;
    assert_eq!(curvy_merkle_new(8, &mut before), CurvyStatus::Ok);

    for _ in 0..REJECTED {
        assert_eq!(
            curvy_merkle_new(8, std::ptr::null_mut()),
            CurvyStatus::InvalidArgument
        );
    }

    let mut after = 0_u64;
    assert_eq!(curvy_merkle_new(8, &mut after), CurvyStatus::Ok);
    assert!(
        after - before < CONCURRENT_NOISE,
        "{REJECTED} rejected calls stranded handles: counter moved {} places",
        after - before
    );

    curvy_merkle_free(before);
    curvy_merkle_free(after);
}

/// A 32-byte big-endian field element from a small integer.
fn field_bytes(value: u64) -> [u8; 32] {
    let mut buffer = [0_u8; 32];
    buffer[24..].copy_from_slice(&value.to_be_bytes());
    buffer
}
