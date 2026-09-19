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

#[test]
fn merkle_verification_rejects_indices_above_the_proof_capacity() {
    use curvy_core::{Fr, field::fr_to_be_32, imt::Imt};
    use curvy_ffi::curvy_verify_merkle_proof;

    for depth in [0, 2] {
        let proof = Imt::from_leaves(depth, &[Fr::from(7u64)]).create_proof(0);
        let leaf = fr_to_be_32(&proof.leaf);
        let root = fr_to_be_32(&proof.root);
        let siblings: Vec<u8> = proof.siblings.iter().flat_map(fr_to_be_32).collect();
        for (index, expected) in [(0, 1), (1 << depth, 0)] {
            let mut valid = -1;
            let status = unsafe {
                curvy_verify_merkle_proof(
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
            assert_eq!(status, CurvyStatus::Ok);
            assert_eq!(valid, expected);
        }
    }
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
    assert_eq!(curvy_witness_graph_free(tree), CurvyStatus::InvalidArgument);
    assert_eq!(curvy_merkle_free(graph), CurvyStatus::InvalidArgument);
    assert_eq!(curvy_merkle_free(tree), CurvyStatus::Ok);
    assert_eq!(curvy_witness_graph_free(graph), CurvyStatus::Ok);
    assert_eq!(curvy_merkle_free(tree), CurvyStatus::InvalidArgument);
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
