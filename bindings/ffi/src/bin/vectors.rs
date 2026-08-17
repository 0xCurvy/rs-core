//! Emits C ABI golden vectors as JSON.
//!
//! `scripts/check-ffi-vectors.mjs` compares this output with the same calls
//! through `curvy-wasm`. The binary calls exported FFI functions directly so it
//! also covers marshalling and ownership.

use std::ffi::{CStr, CString, c_char, c_int};

use curvy_ffi::*;

/// Calls an FFI function and takes ownership of its string output.
fn take_string(call: impl FnOnce(*mut *mut c_char) -> CurvyStatus) -> String {
    let mut out: *mut c_char = std::ptr::null_mut();
    let status = call(&mut out);
    assert_eq!(status, CurvyStatus::Ok, "FFI call failed: {}", last_error());
    assert!(!out.is_null(), "FFI call returned OK with a null string");
    let value = unsafe { CStr::from_ptr(out) }
        .to_str()
        .expect("FFI returned non-UTF-8")
        .to_owned();
    unsafe { curvy_string_free(out) };
    value
}

fn last_error() -> String {
    let ptr = curvy_last_error();
    if ptr.is_null() {
        return "(no error message)".to_string();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn c(value: &str) -> CString {
    CString::new(value).expect("test input contained a NUL")
}

fn json_array(values: &[&str]) -> CString {
    c(&serde_json::to_string(values).expect("could not encode inputs"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Encodes a small integer as one packed field element.
fn field_bytes(value: u64) -> [u8; 32] {
    let mut buffer = [0_u8; 32];
    buffer[24..].copy_from_slice(&value.to_be_bytes());
    buffer
}

fn take_bytes(call: impl FnOnce(*mut CurvyBytes) -> CurvyStatus) -> Vec<u8> {
    let mut out = CurvyBytes {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    let status = call(&mut out);
    assert_eq!(status, CurvyStatus::Ok, "FFI call failed: {}", last_error());
    let value = if out.ptr.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec()
    };
    unsafe { curvy_bytes_free(out) };
    value
}

fn main() {
    let mut report = serde_json::Map::new();

    // Hashing
    let one_two_three = json_array(&["1", "2", "3"]);
    report.insert(
        "poseidon_1_2_3".into(),
        take_string(|out| unsafe { curvy_poseidon(one_two_three.as_ptr(), out) }).into(),
    );

    let single = json_array(&["42"]);
    report.insert(
        "poseidon_42".into(),
        take_string(|out| unsafe { curvy_poseidon(single.as_ptr(), out) }).into(),
    );

    report.insert(
        "sha256_bigint_1_2".into(),
        take_string(|out| unsafe { curvy_sha256_bigint(json_array(&["1", "2"]).as_ptr(), out) })
            .into(),
    );

    let (x, y, secret) = (c("1"), c("2"), c("3"));
    report.insert(
        "owner_hash".into(),
        take_string(|out| unsafe {
            curvy_owner_hash(x.as_ptr(), y.as_ptr(), secret.as_ptr(), out)
        })
        .into(),
    );

    let (owner, amount, token) = (c("7"), c("1000000"), c("5"));
    report.insert(
        "note_id".into(),
        take_string(|out| unsafe {
            curvy_note_id(owner.as_ptr(), amount.as_ptr(), token.as_ptr(), out)
        })
        .into(),
    );

    report.insert(
        "nullifier".into(),
        take_string(|out| unsafe { curvy_nullifier(secret.as_ptr(), x.as_ptr(), y.as_ptr(), out) })
            .into(),
    );

    // BabyJubJub and EdDSA
    // Exact 32-byte key for cross-target account parity.
    let private_key = c("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    report.insert(
        "pub_from_private_key".into(),
        take_string(|out| unsafe { curvy_pub_from_private_key(private_key.as_ptr(), out) }).into(),
    );

    // Canonical scalar below the BabyJubJub subgroup order.
    let scalar = c("2736030358979909402780800718157159386076813972158567259200215660948447373040");
    report.insert(
        "pub_from_scalar".into(),
        take_string(|out| unsafe { curvy_pub_from_scalar(scalar.as_ptr(), out) }).into(),
    );

    report.insert(
        "ephemeral_pub_key".into(),
        take_string(|out| unsafe { curvy_ephemeral_pub_key(c("12345").as_ptr(), out) }).into(),
    );

    let message = c("1234567890");
    report.insert(
        "sign".into(),
        take_string(|out| unsafe { curvy_sign(message.as_ptr(), private_key.as_ptr(), out) })
            .into(),
    );

    report.insert(
        "sign_with_scalar".into(),
        take_string(|out| unsafe {
            curvy_sign_with_scalar(message.as_ptr(), scalar.as_ptr(), out)
        })
        .into(),
    );

    // Note cipher
    let (enc_amount, enc_token, shared, ekx, eky) =
        (c("1000000"), c("5"), c("999"), c("111"), c("222"));
    let encrypted = take_string(|out| unsafe {
        curvy_encrypt_amount_token(
            enc_amount.as_ptr(),
            enc_token.as_ptr(),
            shared.as_ptr(),
            ekx.as_ptr(),
            eky.as_ptr(),
            out,
        )
    });
    report.insert("encrypt_amount_token".into(), encrypted.clone().into());

    // Round-trip through decrypt so a symmetric bug can't cancel itself out.
    let pair: Vec<String> = serde_json::from_str(&encrypted).expect("encrypt returned non-JSON");
    let (cipher_amount, cipher_token) = (c(&pair[0]), c(&pair[1]));
    report.insert(
        "decrypt_amount_token".into(),
        take_string(|out| unsafe {
            curvy_decrypt_amount_token(
                cipher_amount.as_ptr(),
                cipher_token.as_ptr(),
                shared.as_ptr(),
                ekx.as_ptr(),
                eky.as_ptr(),
                out,
            )
        })
        .into(),
    );

    // Stealth
    // Use fixed private keys because `new_meta` and `send` are randomized.
    let (k, v) = (
        c("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        c("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"),
    );
    report.insert(
        "get_meta".into(),
        take_string(|out| unsafe { curvy_get_meta(k.as_ptr(), v.as_ptr(), out) }).into(),
    );

    // Notes-tree geometry
    report.insert("notes_tree_depth".into(), curvy_notes_tree_depth().into());
    report.insert(
        "notes_tree_version".into(),
        curvy_notes_tree_version().into(),
    );
    report.insert(
        "notes_shard_height".into(),
        curvy_notes_shard_height().into(),
    );
    report.insert("notes_shard_size".into(), curvy_notes_shard_size().into());

    // Merkle tree
    // Covers Poseidon, zero hashes, and packed field encoding.
    let mut tree: u64 = 0;
    assert_eq!(curvy_merkle_new(8, &mut tree), CurvyStatus::Ok);
    for leaf in 1_u64..=5 {
        let bytes = field_bytes(leaf);
        let mut index: u32 = 0;
        assert_eq!(
            unsafe { curvy_merkle_insert(tree, bytes.as_ptr(), bytes.len(), &mut index) },
            CurvyStatus::Ok,
            "merkle insert failed: {}",
            last_error()
        );
    }
    report.insert(
        "merkle_root_depth8_leaves1to5".into(),
        hex(&take_bytes(|out| curvy_merkle_root(tree, out))).into(),
    );

    let mut proof: u64 = 0;
    let leaf3 = field_bytes(3);
    assert_eq!(
        unsafe { curvy_merkle_proof(tree, leaf3.as_ptr(), leaf3.len(), &mut proof) },
        CurvyStatus::Ok
    );
    report.insert(
        "merkle_proof_leaf3_siblings".into(),
        hex(&take_bytes(|out| curvy_proof_siblings(proof, out))).into(),
    );

    // Verify the proof instead of comparing two self-consistent outputs.
    let siblings = take_bytes(|out| curvy_proof_siblings(proof, out));
    let root = take_bytes(|out| curvy_merkle_root(tree, out));
    let mut valid: c_int = 0;
    assert_eq!(
        unsafe {
            curvy_verify_merkle_proof(
                leaf3.as_ptr(),
                leaf3.len(),
                2,
                siblings.as_ptr(),
                siblings.len(),
                root.as_ptr(),
                root.len(),
                &mut valid,
            )
        },
        CurvyStatus::Ok
    );
    report.insert("merkle_proof_verifies".into(), (valid == 1).into());
    curvy_proof_free(proof);
    curvy_merkle_free(tree);

    // Sharded notes tree
    let mut sharded: u64 = 0;
    assert_eq!(curvy_sharded_new(10, 2, &mut sharded), CurvyStatus::Ok);
    let packed: Vec<u8> = (1_u64..=9).flat_map(field_bytes).collect();
    assert_eq!(
        unsafe { curvy_sharded_append_many(sharded, packed.as_ptr(), packed.len()) },
        CurvyStatus::Ok,
        "sharded append failed: {}",
        last_error()
    );
    report.insert(
        "sharded_root_depth10_shard2_9notes".into(),
        hex(&take_bytes(|out| curvy_sharded_root(sharded, out))).into(),
    );
    let mut completed: u32 = 0;
    assert_eq!(
        curvy_sharded_completed_shard_count(sharded, &mut completed),
        CurvyStatus::Ok
    );
    report.insert("sharded_completed_shard_count".into(), completed.into());
    curvy_sharded_free(sharded);

    // Frontier
    let mut frontier: u64 = 0;
    assert_eq!(curvy_frontier_new(10, 2, &mut frontier), CurvyStatus::Ok);
    let _ = take_bytes(|out| unsafe {
        curvy_frontier_append_many(frontier, packed.as_ptr(), packed.len(), out)
    });
    report.insert(
        "frontier_root_depth10_shard2_9notes".into(),
        hex(&take_bytes(|out| curvy_frontier_root(frontier, out))).into(),
    );
    curvy_frontier_free(frontier);

    report.insert(
        "version".into(),
        take_string(|out| curvy_version(out)).into(),
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("could not encode report")
    );
}
