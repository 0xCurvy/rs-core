use std::ffi::{CStr, CString, c_char};

use curvy_ffi::{
    CurvyBytes, CurvyStatus, curvy_bytes_free, curvy_last_error, curvy_merkle_free,
    curvy_merkle_leaves, curvy_merkle_new, curvy_pub_from_private_key, curvy_resident_prover_free,
    curvy_resident_prover_mode, curvy_resident_prover_new, curvy_resident_prover_profile,
    curvy_sharded_append_many, curvy_sharded_drain_dirty_owned_notes, curvy_sharded_free,
    curvy_sharded_mark_owned, curvy_sharded_new, curvy_sharded_owned_note_count, curvy_string_free,
    curvy_witness_graph_calculate_packed, curvy_witness_graph_free, curvy_witness_graph_new,
};
use curvy_witness::Limits;
use curvy_witness::wire::{FIELD_BN254_FR, FORMAT_VERSION_V1, HEADER_SIZE, MAGIC};
use sha2::{Digest, Sha256};

const ZKEY: &[u8] = include_bytes!("../../../crates/prover/testdata/multiplier.zkey");
const ZKEY_SHA256: &str = "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f";

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

/// Calls `curvy_verify_merkle_proof` with packed fields and returns `out`.
fn verify_merkle(
    depth: u32,
    leaf: &curvy_core::Fr,
    index: u32,
    siblings: &[curvy_core::Fr],
    root: &curvy_core::Fr,
) -> i32 {
    use curvy_core::field::fr_to_be_32;
    let leaf = fr_to_be_32(leaf);
    let root = fr_to_be_32(root);
    let siblings: Vec<u8> = siblings.iter().flat_map(fr_to_be_32).collect();
    let mut valid = -1;
    let status = unsafe {
        curvy_ffi::curvy_verify_merkle_proof(
            depth,
            leaf.as_ptr(),
            leaf.len(),
            index,
            siblings.as_ptr(),
            siblings.len(),
            root.as_ptr(),
            root.len(),
            &mut valid,
        )
    };
    assert_eq!(status, CurvyStatus::Ok, "{}", last_error());
    valid
}

#[test]
fn merkle_verification_rejects_indices_above_the_proof_capacity() {
    use curvy_core::{Fr, imt::Imt};

    for depth in [0, 2] {
        let proof = Imt::from_leaves(depth, &[Fr::from(7u64)]).create_proof(0);
        for (index, expected) in [(0, 1), (1 << depth, 0)] {
            assert_eq!(
                verify_merkle(
                    depth as u32,
                    &proof.leaf,
                    index,
                    &proof.siblings,
                    &proof.root
                ),
                expected
            );
        }
    }
}

/// The caller's expected depth, not the proof's sibling count, fixes the tree
/// height: an internal node or the root itself must not pass as a leaf.
#[test]
fn merkle_verification_pins_the_expected_depth() {
    use curvy_core::{Fr, imt::Imt, poseidon};

    let depth = 6;
    let leaves: Vec<Fr> = (1u64..=11).map(Fr::from).collect();
    let tree = Imt::from_leaves(depth, &leaves);
    let root = tree.root();
    let full = tree.create_proof(2);
    assert_eq!(verify_merkle(6, &full.leaf, 2, &full.siblings, &root), 1);
    for wrong_depth in [0, 5, 7, u32::MAX] {
        assert_eq!(
            verify_merkle(wrong_depth, &full.leaf, 2, &full.siblings, &root),
            0
        );
    }

    // The level-1 node over leaves 2 and 3, proven with the top siblings.
    let internal = poseidon(&[leaves[2], leaves[3]]);
    assert_eq!(
        verify_merkle(6, &internal, 1, &full.siblings[1..], &root),
        0
    );
    // A zero-sibling proof that the root is its own leaf.
    assert_eq!(verify_merkle(6, &root, 0, &[], &root), 0);
    // ...which is exactly a genuine depth-0 tree.
    assert_eq!(verify_merkle(0, &root, 0, &[], &root), 1);
}

#[test]
fn merkle_verification_rejects_malformed_encodings_as_invalid_arguments() {
    use curvy_ffi::curvy_verify_merkle_proof;

    let field = field_bytes(7);
    let noncanonical = [0xff_u8; 32];
    let mut valid = -1;
    for (leaf, leaf_len, siblings_len) in [
        (std::ptr::null(), 32, 0),
        (field.as_ptr(), 31, 0),
        (field.as_ptr(), 32, 31),
        (noncanonical.as_ptr(), 32, 0),
    ] {
        let status = unsafe {
            curvy_verify_merkle_proof(
                0,
                leaf,
                leaf_len,
                0,
                field.as_ptr(),
                siblings_len,
                field.as_ptr(),
                field.len(),
                &mut valid,
            )
        };
        assert_eq!(status, CurvyStatus::InvalidArgument);
        assert!(!last_error().is_empty());
    }
    assert_eq!(valid, -1);
    let status = unsafe {
        curvy_verify_merkle_proof(
            0,
            field.as_ptr(),
            field.len(),
            0,
            std::ptr::null(),
            0,
            field.as_ptr(),
            field.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, CurvyStatus::InvalidArgument);
    assert_eq!(last_error(), "null output pointer");
}

#[test]
fn depth_zero_merkle_handle_starts_empty_and_accepts_one_leaf() {
    use curvy_ffi::{curvy_merkle_insert, curvy_merkle_leaf_count, curvy_merkle_truncate};

    let mut tree = 0;
    assert_eq!(curvy_merkle_new(0, &mut tree), CurvyStatus::Ok);
    let mut count = u32::MAX;
    assert_eq!(curvy_merkle_leaf_count(tree, &mut count), CurvyStatus::Ok);
    assert_eq!(count, 0);
    let mut leaf = [0; 32];
    leaf[31] = 7;
    let mut index = u32::MAX;
    assert_eq!(
        unsafe { curvy_merkle_insert(tree, leaf.as_ptr(), leaf.len(), &mut index) },
        CurvyStatus::Ok
    );
    assert_eq!(index, 0);
    leaf[31] = 8;
    assert_eq!(
        unsafe { curvy_merkle_insert(tree, leaf.as_ptr(), leaf.len(), &mut index) },
        CurvyStatus::Error
    );
    assert_eq!(curvy_merkle_leaf_count(tree, &mut count), CurvyStatus::Ok);
    assert_eq!(count, 1);
    assert_eq!(curvy_merkle_truncate(tree, 0), CurvyStatus::Ok);
    assert_eq!(curvy_merkle_leaf_count(tree, &mut count), CurvyStatus::Ok);
    assert_eq!(count, 0);
    curvy_merkle_free(tree);
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

#[test]
fn witness_assignments_have_a_packed_binary_boundary() {
    let graph = multiplier_graph();
    let sha = sha256_hex(&graph);
    let mut handle = 0_u64;
    assert_eq!(
        unsafe {
            curvy_witness_graph_new(
                graph.as_ptr(),
                graph.len(),
                sha.as_ptr(),
                false,
                &mut handle,
            )
        },
        CurvyStatus::Ok
    );

    let input = CString::new(r#"{"a":"3","b":"11"}"#).unwrap();
    let mut out = CurvyBytes::empty();
    assert_eq!(
        unsafe { curvy_witness_graph_calculate_packed(handle, input.as_ptr(), &mut out) },
        CurvyStatus::Ok
    );
    let assignment = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
    assert_eq!(assignment.len(), 4 * 32);
    assert_eq!(assignment[0..32], field_bytes(1));
    assert_eq!(assignment[32..64], field_bytes(33));
    assert_eq!(assignment[64..96], field_bytes(3));
    assert_eq!(assignment[96..128], field_bytes(11));
    unsafe { curvy_bytes_free(out) };
    let bad = CString::new(r#"{"a":"PRIVATE_SENTINEL!","b":"11"}"#).unwrap();
    let mut rejected = CurvyBytes::empty();
    assert_eq!(
        unsafe { curvy_witness_graph_calculate_packed(handle, bad.as_ptr(), &mut rejected) },
        CurvyStatus::Error
    );
    assert!(rejected.ptr.is_null());
    assert!(!last_error().contains("PRIVATE_SENTINEL"));
    curvy_witness_graph_free(handle);
}

#[test]
fn resident_prover_reports_hawk_identity() {
    let graph = multiplier_graph();
    let graph_sha = sha256_hex(&graph);
    let zkey_sha = CString::new(ZKEY_SHA256).unwrap();
    let mut handle = 0_u64;
    assert_eq!(
        unsafe {
            curvy_resident_prover_new(
                ZKEY.as_ptr(),
                ZKEY.len(),
                zkey_sha.as_ptr(),
                graph.as_ptr(),
                graph.len(),
                graph_sha.as_ptr(),
                &mut handle,
            )
        },
        CurvyStatus::Ok
    );

    for (getter, expected) in [
        (
            curvy_resident_prover_mode
                as unsafe extern "C" fn(u64, *mut *mut c_char) -> CurvyStatus,
            "resident",
        ),
        (curvy_resident_prover_profile, "HAWK"),
    ] {
        let mut value = std::ptr::null_mut();
        assert_eq!(unsafe { getter(handle, &mut value) }, CurvyStatus::Ok);
        assert_eq!(unsafe { CStr::from_ptr(value) }.to_str().unwrap(), expected);
        unsafe { curvy_string_free(value) };
    }

    curvy_resident_prover_free(handle);
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

fn multiplier_graph() -> Vec<u8> {
    let mut graph = Vec::new();
    graph.extend_from_slice(b"CVYWIT01");
    graph.extend_from_slice(&1_u16.to_le_bytes());
    graph.extend_from_slice(&1_u16.to_le_bytes());
    graph.extend_from_slice(&64_u32.to_le_bytes());
    graph.extend_from_slice(&[0_u8; 32]);
    graph.extend_from_slice(&4_u32.to_le_bytes());
    graph.extend_from_slice(&4_u32.to_le_bytes());
    graph.extend_from_slice(&2_u32.to_le_bytes());
    graph.extend_from_slice(&3_u32.to_le_bytes());

    for input in 0_u32..=2 {
        graph.push(0);
        graph.extend_from_slice(&input.to_le_bytes());
    }
    graph.push(2);
    graph.push(0);
    graph.extend_from_slice(&1_u32.to_le_bytes());
    graph.extend_from_slice(&2_u32.to_le_bytes());
    for signal in [0_u32, 3, 1, 2] {
        graph.extend_from_slice(&signal.to_le_bytes());
    }
    for (name, signal) in [("a", 1_u32), ("b", 2_u32)] {
        graph.extend_from_slice(&fnv1a(name).to_le_bytes());
        graph.extend_from_slice(&signal.to_le_bytes());
        graph.extend_from_slice(&1_u32.to_le_bytes());
    }
    graph
}

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF29CE484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3)
    })
}

#[test]
fn resident_sage_constructors_authenticate_and_prove() {
    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    use curvy_ffi::{
        curvy_resident_prover_new_compiled_sage, curvy_resident_prover_new_sage,
        curvy_resident_prover_prove,
    };
    use curvy_witness::sage::SageGraph;
    let graph = multiplier_graph();
    let graph_hash = digest(&graph);
    let sage = SageGraph::from_bytes(&graph, &graph_hash).unwrap();
    let program = sage.to_compiled_bytes().unwrap();
    let program_hash = CString::new(digest(&program)).unwrap();
    let zkey_hash = CString::new(digest(ZKEY)).unwrap();
    let graph_hash = CString::new(graph_hash).unwrap();
    let wrong = CString::new("00".repeat(32)).unwrap();
    let mut handle = 0;
    unsafe {
        assert_eq!(
            curvy_resident_prover_new_sage(
                ZKEY.as_ptr(),
                ZKEY.len(),
                zkey_hash.as_ptr(),
                graph.as_ptr(),
                graph.len(),
                graph_hash.as_ptr(),
                std::ptr::null_mut()
            ),
            CurvyStatus::InvalidArgument
        );
        assert_eq!(
            curvy_resident_prover_new_sage(
                ZKEY.as_ptr(),
                ZKEY.len(),
                zkey_hash.as_ptr(),
                graph.as_ptr(),
                graph.len(),
                graph_hash.as_ptr(),
                &mut handle
            ),
            CurvyStatus::Ok
        );
        curvy_resident_prover_free(handle);
        for (program_pin, source_pin) in [(&wrong, &graph_hash), (&program_hash, &wrong)] {
            assert_eq!(
                curvy_resident_prover_new_compiled_sage(
                    ZKEY.as_ptr(),
                    ZKEY.len(),
                    zkey_hash.as_ptr(),
                    program.as_ptr(),
                    program.len(),
                    program_pin.as_ptr(),
                    source_pin.as_ptr(),
                    &mut handle
                ),
                CurvyStatus::Error
            );
        }
        assert_eq!(
            curvy_resident_prover_new_compiled_sage(
                ZKEY.as_ptr(),
                ZKEY.len(),
                zkey_hash.as_ptr(),
                program.as_ptr(),
                program.len(),
                program_hash.as_ptr(),
                graph_hash.as_ptr(),
                &mut handle
            ),
            CurvyStatus::Ok
        );
        let input = CString::new(r#"{"a":"3","b":"11"}"#).unwrap();
        let mut output = std::ptr::null_mut();
        assert_eq!(
            curvy_resident_prover_prove(handle, input.as_ptr(), &mut output),
            CurvyStatus::Ok
        );
        assert!(CStr::from_ptr(output).to_str().unwrap().contains("33"));
        curvy_string_free(output);
        curvy_resident_prover_free(handle);
    }
}

#[test]
fn malformed_secret_boundaries_do_not_panic_or_log_inputs() {
    if std::env::var_os("CURVY_BOUNDARY_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "malformed_secret_boundaries_do_not_panic_or_log_inputs",
                "--nocapture",
            ])
            .env("CURVY_BOUNDARY_CHILD", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "child regression failed");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panic"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_SENTINEL"));
        return;
    }
    use curvy_ffi::*;
    let secret = CString::new("PRIVATE_SENTINEL_123!").unwrap();
    let one = CString::new("1").unwrap();
    let key = CString::new("ab".repeat(32)).unwrap();
    let bad_list = CString::new("[\"PRIVATE_SENTINEL_123!\"]").unwrap();
    let empty = CString::new("[]").unwrap();
    let huge = CString::new("9".repeat(79)).unwrap();
    let mut out = std::ptr::null_mut();
    let (s, o) = (secret.as_ptr(), one.as_ptr());
    let results = unsafe {
        [
            curvy_owner_hash(o, o, s, &mut out),
            curvy_note_id(s, o, o, &mut out),
            curvy_nullifier(s, o, o, &mut out),
            curvy_ephemeral_pub_key(s, &mut out),
            curvy_sign(s, key.as_ptr(), &mut out),
            curvy_poseidon(bad_list.as_ptr(), &mut out),
            curvy_sha256_bigint(bad_list.as_ptr(), &mut out),
            curvy_poseidon(empty.as_ptr(), &mut out),
            curvy_encrypt_amount_token(o, o, s, o, o, &mut out),
            curvy_decrypt_amount_token(o, o, s, o, o, &mut out),
            curvy_sign(huge.as_ptr(), key.as_ptr(), &mut out),
        ]
    };
    for status in results {
        assert_eq!(status, CurvyStatus::InvalidArgument);
    }
    assert!(out.is_null());
    assert!(!last_error().contains("PRIVATE_SENTINEL"));
}

/// Malformed pointers, UTF-8, and decimal inputs share one status, whether the
/// entry point parses them directly or through a fallible core constructor.
#[test]
fn malformed_inputs_are_invalid_arguments_with_a_message() {
    use curvy_ffi::{
        curvy_get_meta, curvy_pub_from_scalar, curvy_scan, curvy_sign_with_scalar,
        curvy_verify_scalar_signature,
    };
    let abc = CString::new("abc").unwrap();
    let one = CString::new("1").unwrap();
    let not_utf8 = [0xff_u8, 0];
    let mut out: *mut c_char = std::ptr::null_mut();
    for scalar in [std::ptr::null(), abc.as_ptr(), not_utf8.as_ptr().cast()] {
        assert_eq!(
            unsafe { curvy_pub_from_scalar(scalar, &mut out) },
            CurvyStatus::InvalidArgument
        );
        assert!(!last_error().is_empty());
        assert_eq!(
            unsafe { curvy_sign_with_scalar(one.as_ptr(), scalar, &mut out) },
            CurvyStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { curvy_sign_with_scalar(scalar, one.as_ptr(), &mut out) },
            CurvyStatus::InvalidArgument
        );
        let mut valid = -1;
        assert_eq!(
            unsafe {
                curvy_verify_scalar_signature(
                    scalar,
                    one.as_ptr(),
                    one.as_ptr(),
                    one.as_ptr(),
                    one.as_ptr(),
                    one.as_ptr(),
                    &mut valid,
                )
            },
            CurvyStatus::InvalidArgument
        );
        assert_eq!(valid, -1);
        assert_eq!(
            unsafe { curvy_get_meta(scalar, scalar, &mut out) },
            CurvyStatus::InvalidArgument
        );
    }
    let empty = CString::new("[]").unwrap();
    assert_eq!(
        unsafe {
            curvy_scan(
                abc.as_ptr(),
                abc.as_ptr(),
                empty.as_ptr(),
                empty.as_ptr(),
                &mut out,
            )
        },
        CurvyStatus::InvalidArgument
    );
    assert!(out.is_null());

    let mut handle = 0;
    assert_eq!(
        unsafe { curvy_witness_graph_new(std::ptr::null(), 64, abc.as_ptr(), false, &mut handle) },
        CurvyStatus::InvalidArgument
    );
    assert_eq!(last_error(), "invalid graph buffer");
    assert_eq!(handle, 0);
}

/// Every fallible call replaces the previous message, including early
/// out-pointer rejections that never reach the call body.
#[test]
fn rejected_out_pointers_replace_the_previous_error() {
    use curvy_ffi::{curvy_merkle_insert, curvy_merkle_proof_at};

    let stale = || {
        let key = CString::new("0xab").unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        assert_eq!(
            unsafe { curvy_pub_from_private_key(key.as_ptr(), &mut out) },
            CurvyStatus::InvalidArgument
        );
        assert!(last_error().contains("remove the leading 0x"));
    };

    stale();
    assert_eq!(
        curvy_merkle_new(8, std::ptr::null_mut()),
        CurvyStatus::InvalidArgument
    );
    assert_eq!(last_error(), "null output pointer");

    let mut tree = 0;
    assert_eq!(curvy_merkle_new(8, &mut tree), CurvyStatus::Ok);
    let leaf = field_bytes(1);
    stale();
    assert_eq!(
        unsafe { curvy_merkle_insert(tree, leaf.as_ptr(), leaf.len(), std::ptr::null_mut()) },
        CurvyStatus::InvalidArgument
    );
    assert_eq!(last_error(), "null output pointer");
    stale();
    assert_eq!(
        curvy_merkle_proof_at(tree, 0, std::ptr::null_mut()),
        CurvyStatus::InvalidArgument
    );
    assert_eq!(last_error(), "null output pointer");
    stale();
    assert_eq!(curvy_merkle_free(tree), CurvyStatus::Ok);
    assert!(curvy_last_error().is_null());
}

/// The point at infinity ("0.0") is never a key or announcement: scans skip it,
/// sends reject it, and the validator refuses it, all without panicking.
#[test]
fn identity_points_are_rejected_or_skipped_without_panicking() {
    use curvy_ffi::{
        curvy_get_meta, curvy_is_valid_bn254_point, curvy_is_valid_secp256k1_point, curvy_scan,
        curvy_send, curvy_viewer_scan,
    };

    let identity = CString::new("0.0").unwrap();
    assert_eq!(unsafe { curvy_is_valid_bn254_point(identity.as_ptr()) }, 0);
    assert_eq!(
        unsafe { curvy_is_valid_secp256k1_point(identity.as_ptr()) },
        0
    );

    let k =
        CString::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
    let v =
        CString::new("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210").unwrap();
    let mut out: *mut c_char = std::ptr::null_mut();
    assert_eq!(
        unsafe { curvy_get_meta(k.as_ptr(), v.as_ptr(), &mut out) },
        CurvyStatus::Ok
    );
    let meta: Vec<String> =
        serde_json::from_str(unsafe { CStr::from_ptr(out) }.to_str().unwrap()).unwrap();
    unsafe { curvy_string_free(out) };
    let (big_k, big_v) = (
        CString::new(meta[2].as_str()).unwrap(),
        CString::new(meta[3].as_str()).unwrap(),
    );

    let rs = CString::new(r#"["0.0"]"#).unwrap();
    let tags = CString::new(r#"["00"]"#).unwrap();
    for status in unsafe {
        [
            curvy_scan(k.as_ptr(), v.as_ptr(), rs.as_ptr(), tags.as_ptr(), &mut out),
            curvy_viewer_scan(
                v.as_ptr(),
                big_k.as_ptr(),
                rs.as_ptr(),
                tags.as_ptr(),
                &mut out,
            ),
        ]
    } {
        assert_eq!(status, CurvyStatus::Ok);
    }
    // Both calls wrote `[]`; the second overwrote the first pointer.
    assert_eq!(unsafe { CStr::from_ptr(out) }.to_str().unwrap(), "[]");
    unsafe { curvy_string_free(out) };

    out = std::ptr::null_mut();
    for (spend, view) in [
        (identity.as_ptr(), big_v.as_ptr()),
        (big_k.as_ptr(), identity.as_ptr()),
    ] {
        assert_eq!(
            unsafe { curvy_send(spend, view, &mut out) },
            CurvyStatus::InvalidArgument
        );
        assert!(last_error().contains("point at infinity"));
        assert!(out.is_null());
    }
    assert_eq!(
        unsafe {
            curvy_viewer_scan(
                v.as_ptr(),
                identity.as_ptr(),
                rs.as_ptr(),
                tags.as_ptr(),
                &mut out,
            )
        },
        CurvyStatus::InvalidArgument
    );
    assert!(out.is_null());
}

/// Hosts free handles from thread-local destructors (C++ `thread_local` RAII,
/// Swift teardown) that can run after the library's own thread-locals are gone.
/// That must not abort the process.
#[test]
fn frees_from_thread_local_destructors_do_not_abort() {
    const TEST: &str = "frees_from_thread_local_destructors_do_not_abort";
    if std::env::var_os("CURVY_TLS_TEARDOWN_CHILD").is_none() {
        // An abort takes the whole test binary down, so run in a child process.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("CURVY_TLS_TEARDOWN_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }

    use std::cell::Cell;
    use std::sync::atomic::{AtomicI32, Ordering};

    static FREED: AtomicI32 = AtomicI32::new(-1);
    static FREED_AGAIN: AtomicI32 = AtomicI32::new(-1);
    static FAILED_CALL: AtomicI32 = AtomicI32::new(-1);

    struct FreeOnThreadExit(Cell<u64>);
    impl Drop for FreeOnThreadExit {
        fn drop(&mut self) {
            let handle = self.0.get();
            FREED.store(curvy_merkle_free(handle) as i32, Ordering::SeqCst);
            FREED_AGAIN.store(curvy_merkle_free(handle) as i32, Ordering::SeqCst);
            FAILED_CALL.store(
                curvy_merkle_new(8, std::ptr::null_mut()) as i32,
                Ordering::SeqCst,
            );
            let _ = curvy_last_error();
        }
    }
    thread_local! {
        static OWNER: FreeOnThreadExit = const { FreeOnThreadExit(Cell::new(0)) };
    }

    std::thread::spawn(|| {
        // Register this destructor before the library first touches its error
        // slot on this thread, so the slot is destroyed first.
        OWNER.with(|_| ());
        let mut handle = 0;
        assert_eq!(curvy_merkle_new(8, &mut handle), CurvyStatus::Ok);
        OWNER.with(|owner| owner.0.set(handle));
    })
    .join()
    .unwrap();

    assert_eq!(FREED.load(Ordering::SeqCst), CurvyStatus::Ok as i32);
    assert_eq!(
        FREED_AGAIN.load(Ordering::SeqCst),
        CurvyStatus::InvalidHandle as i32
    );
    assert_eq!(
        FAILED_CALL.load(Ordering::SeqCst),
        CurvyStatus::InvalidArgument as i32
    );
}

#[test]
fn wrong_type_free_cannot_destroy_another_registry_object() {
    let mut tree = 0;
    let mut graph = 0;
    assert_eq!(curvy_merkle_new(8, &mut tree), CurvyStatus::Ok);
    let bytes = multiplier_graph();
    let pin = sha256_hex(&bytes);
    assert_eq!(
        unsafe {
            curvy_witness_graph_new(bytes.as_ptr(), bytes.len(), pin.as_ptr(), false, &mut graph)
        },
        CurvyStatus::Ok
    );
    assert_ne!(tree, graph);
    assert_eq!(curvy_witness_graph_free(tree), CurvyStatus::InvalidHandle);
    assert_eq!(curvy_merkle_free(graph), CurvyStatus::InvalidHandle);
    assert_eq!(curvy_merkle_free(tree), CurvyStatus::Ok);
    assert_eq!(curvy_witness_graph_free(graph), CurvyStatus::Ok);
    assert_eq!(curvy_merkle_free(tree), CurvyStatus::InvalidHandle);
    assert!(last_error().contains("unknown, freed, or wrong-type handle"));
}

#[test]
fn handle_outputs_support_unaligned_c_storage() {
    let mut storage = [0_u8; 16];
    let offset = if (storage.as_ptr() as usize).is_multiple_of(8) {
        1
    } else {
        0
    };
    let output = unsafe { storage.as_mut_ptr().add(offset) }.cast::<u64>();
    assert!(!(output as usize).is_multiple_of(8));
    assert_eq!(curvy_merkle_new(8, output), CurvyStatus::Ok);
    let handle = unsafe { std::ptr::read_unaligned(output) };
    assert_eq!(curvy_merkle_free(handle), CurvyStatus::Ok);
}

#[test]
fn ephemeral_public_key_accepts_u256_and_rejects_overflow_without_panicking() {
    use curvy_core::{
        babyjubjub::{BASE8, mul_point_escalar},
        encoding::try_dec_to_u256,
        field::fr_to_dec,
    };
    use curvy_ffi::curvy_ephemeral_pub_key;
    for value in [
        "0",
        "1",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    ] {
        let scalar = try_dec_to_u256(value).unwrap();
        let expected = mul_point_escalar(*BASE8, &scalar);
        let input = CString::new(value).unwrap();
        let mut output = std::ptr::null_mut();
        assert_eq!(
            unsafe { curvy_ephemeral_pub_key(input.as_ptr(), &mut output) },
            CurvyStatus::Ok
        );
        let actual: Vec<String> =
            serde_json::from_str(unsafe { CStr::from_ptr(output) }.to_str().unwrap()).unwrap();
        unsafe { curvy_string_free(output) };
        assert_eq!(actual, vec![fr_to_dec(&expected.0), fr_to_dec(&expected.1)]);
    }
    let input = CString::new(
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    )
    .unwrap();
    let mut output = std::ptr::null_mut();
    assert_eq!(
        unsafe { curvy_ephemeral_pub_key(input.as_ptr(), &mut output) },
        CurvyStatus::InvalidArgument
    );
    assert!(output.is_null());
    assert!(!last_error().contains(input.to_str().unwrap()));
}
