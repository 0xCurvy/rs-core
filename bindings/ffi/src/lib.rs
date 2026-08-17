//! C ABI for Curvy mobile and embedded hosts.
//!
//! The boundary mirrors `curvy-wasm`: scalars use decimal strings and bulk
//! Merkle data uses packed 32-byte big-endian fields. Conformance tests keep the
//! two APIs aligned.

mod abi;
mod registry;

// The vector binary links the rlib, so these exports must also be public Rust items.
pub mod prover;
pub mod trees;

pub use prover::*;
pub use trees::*;

use std::ffi::{c_char, c_int};

use curvy_core::babyjubjub::{BabyJubPoint, BabyJubScalar};
use curvy_core::cipher::{decrypt_amount_token, encrypt_amount_token};
use curvy_core::eddsa::{
    ScalarSignature, ScalarSigningKey, ephemeral_pub_key, pub_from_private_key_hex, sign_hex,
    verify_scalar_compat,
};
use curvy_core::encoding::dec_to_biguint;
use curvy_core::field::{Bn254Fr, fr_from_dec, fr_to_dec};
use curvy_core::hash_utils::sha256_bigint as core_sha256_bigint;
use curvy_core::note;
use curvy_core::poseidon::poseidon as core_poseidon;
use curvy_core::stealth;

use abi::{guard, guard_result, str_in, str_vec_in, str_vec_out, string_out};

pub use abi::{CurvyBytes, CurvyStatus, curvy_bytes_free, curvy_last_error, curvy_string_free};

/// Returns the boundary version shared with `curvy-wasm`.
#[unsafe(no_mangle)]
pub extern "C" fn curvy_version(out: *mut *mut c_char) -> CurvyStatus {
    guard(|| string_out("v1.0.2".to_string(), out))
}

/// Verifies that the native library is linked. Safe to call more than once.
#[unsafe(no_mangle)]
pub extern "C" fn curvy_init() -> CurvyStatus {
    CurvyStatus::Ok
}

// Hashing

/// # Safety
/// `inputs_json` must be a NUL-terminated JSON array of decimal strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_poseidon(
    inputs_json: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let inputs = match unsafe { str_vec_in(inputs_json) } {
            Ok(values) => values,
            Err(status) => return status,
        };
        let elements: Vec<_> = inputs.iter().map(|value| fr_from_dec(value)).collect();
        string_out(fr_to_dec(&core_poseidon(&elements)), out)
    })
}

/// Hashes raw 256-bit decimal inputs without field reduction.
///
/// # Safety
/// `inputs_json` must be a NUL-terminated JSON array of decimal strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sha256_bigint(
    inputs_json: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let inputs = match unsafe { str_vec_in(inputs_json) } {
            Ok(values) => values,
            Err(status) => return status,
        };
        let integers: Vec<_> = inputs.iter().map(|value| dec_to_biguint(value)).collect();
        string_out(core_sha256_bigint(&integers).to_string(), out)
    })
}

/// # Safety
/// All pointers must be NUL-terminated UTF-8 decimal strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_owner_hash(
    pub_x: *const c_char,
    pub_y: *const c_char,
    shared_secret: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let (pub_x, pub_y, shared_secret) =
            match unsafe { (str_in(pub_x), str_in(pub_y), str_in(shared_secret)) } {
                (Ok(x), Ok(y), Ok(secret)) => (x, y, secret),
                _ => return CurvyStatus::InvalidArgument,
            };
        string_out(
            fr_to_dec(&note::owner_hash(
                (fr_from_dec(pub_x), fr_from_dec(pub_y)),
                fr_from_dec(shared_secret),
            )),
            out,
        )
    })
}

/// # Safety
/// All pointers must be NUL-terminated UTF-8 decimal strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_note_id(
    owner_hash: *const c_char,
    amount: *const c_char,
    token: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let (owner_hash, amount, token) =
            match unsafe { (str_in(owner_hash), str_in(amount), str_in(token)) } {
                (Ok(hash), Ok(amount), Ok(token)) => (hash, amount, token),
                _ => return CurvyStatus::InvalidArgument,
            };
        string_out(
            fr_to_dec(&note::note_id(
                fr_from_dec(owner_hash),
                fr_from_dec(amount),
                fr_from_dec(token),
            )),
            out,
        )
    })
}

/// # Safety
/// All pointers must be NUL-terminated UTF-8 decimal strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_nullifier(
    shared_secret: *const c_char,
    pub_x: *const c_char,
    pub_y: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let (shared_secret, pub_x, pub_y) =
            match unsafe { (str_in(shared_secret), str_in(pub_x), str_in(pub_y)) } {
                (Ok(secret), Ok(x), Ok(y)) => (secret, x, y),
                _ => return CurvyStatus::InvalidArgument,
            };
        string_out(
            fr_to_dec(&note::nullifier(
                fr_from_dec(shared_secret),
                (fr_from_dec(pub_x), fr_from_dec(pub_y)),
            )),
            out,
        )
    })
}

// BabyJubJub and EdDSA

/// `[x, y]` from a hex private key.
///
/// # Safety
/// `private_key_hex` must be a NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_pub_from_private_key(
    private_key_hex: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let hex = match unsafe { str_in(private_key_hex) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let (x, y) = match pub_from_private_key_hex(hex) {
            Ok(point) => point,
            Err(error) => {
                crate::abi::set_last_error(format!("invalid EdDSA private key: {error}"));
                return CurvyStatus::InvalidArgument;
            }
        };
        str_vec_out(vec![fr_to_dec(&x), fr_to_dec(&y)], out)
    })
}

/// Returns `[x, y] = scalar * Base8` without seed derivation.
///
/// # Safety
/// `scalar` must be a NUL-terminated UTF-8 decimal string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_pub_from_scalar(
    scalar: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard_result(
        || {
            let scalar =
                unsafe { str_in(scalar) }.map_err(|_| "invalid scalar string".to_string())?;
            let key = ScalarSigningKey::from_decimal(scalar).map_err(|e| e.to_string())?;
            let public = key.verifying_key();
            Ok(vec![fr_to_dec(&public.x()), fr_to_dec(&public.y())])
        },
        |values| str_vec_out(values, out),
    )
}

/// Returns `R = scalar * Base8` as `[x, y]`.
///
/// # Safety
/// `scalar` must be a NUL-terminated UTF-8 decimal string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_ephemeral_pub_key(
    scalar: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let scalar = match unsafe { str_in(scalar) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let (x, y) = ephemeral_pub_key(&dec_to_biguint(scalar));
        str_vec_out(vec![fr_to_dec(&x), fr_to_dec(&y)], out)
    })
}

/// EdDSA-Poseidon signature `[R8.x, R8.y, S]` from a hex private key.
///
/// # Safety
/// Both pointers must be NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sign(
    message: *const c_char,
    private_key_hex: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let (message, hex) = match unsafe { (str_in(message), str_in(private_key_hex)) } {
            (Ok(message), Ok(hex)) => (message, hex),
            _ => return CurvyStatus::InvalidArgument,
        };
        let signature = match sign_hex(&dec_to_biguint(message), hex) {
            Ok(signature) => signature,
            Err(error) => {
                crate::abi::set_last_error(format!("invalid EdDSA private key: {error}"));
                return CurvyStatus::InvalidArgument;
            }
        };
        str_vec_out(
            vec![
                fr_to_dec(&signature.r8.0),
                fr_to_dec(&signature.r8.1),
                signature.s.to_string(),
            ],
            out,
        )
    })
}

/// Direct-scalar Curvy signature `[R8.x, R8.y, S]`.
///
/// # Safety
/// Both pointers must be NUL-terminated UTF-8 decimal strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_sign_with_scalar(
    message: *const c_char,
    scalar: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard_result(
        || {
            let (message, scalar) = unsafe { (str_in(message), str_in(scalar)) };
            let message = message.map_err(|_| "invalid message string".to_string())?;
            let scalar = scalar.map_err(|_| "invalid scalar string".to_string())?;
            let message = Bn254Fr::try_from_dec(message).map_err(|e| e.to_string())?;
            let key = ScalarSigningKey::from_decimal(scalar).map_err(|e| e.to_string())?;
            let signature = key.sign_curvy_v1(message).map_err(|e| e.to_string())?;
            Ok(vec![
                fr_to_dec(&signature.r8.x()),
                fr_to_dec(&signature.r8.y()),
                signature.s.to_dec(),
            ])
        },
        |values| str_vec_out(values, out),
    )
}

/// Verify a scalar-native Curvy signature.
///
/// Malformed or non-canonical inputs are an error; a well-formed but invalid
/// signature writes `0` and returns `Ok`. Conflating the two would let a
/// verification failure look like a parse failure.
///
/// # Safety
/// All pointers must be NUL-terminated UTF-8 decimal strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_verify_scalar_signature(
    message: *const c_char,
    public_x: *const c_char,
    public_y: *const c_char,
    r8_x: *const c_char,
    r8_y: *const c_char,
    s: *const c_char,
    out: *mut c_int,
) -> CurvyStatus {
    guard_result(
        || {
            let read = |ptr| unsafe { str_in(ptr) }.map_err(|_| "invalid string".to_string());
            let message = Bn254Fr::try_from_dec(read(message)?).map_err(|e| e.to_string())?;
            let public = BabyJubPoint::try_from_dec(read(public_x)?, read(public_y)?)
                .map_err(|e| e.to_string())?;
            let r8 =
                BabyJubPoint::try_from_dec(read(r8_x)?, read(r8_y)?).map_err(|e| e.to_string())?;
            let s = BabyJubScalar::try_from_dec(read(s)?).map_err(|e| e.to_string())?;
            Ok(verify_scalar_compat(
                message,
                &public,
                &ScalarSignature { r8, s },
            ))
        },
        |valid| {
            if out.is_null() {
                return CurvyStatus::InvalidArgument;
            }
            unsafe { *out = c_int::from(valid) };
            CurvyStatus::Ok
        },
    )
}

// Note cipher

/// Maps `(amount, token)` to `[encryptedAmount, encryptedToken]`.
///
/// # Safety
/// All pointers must be NUL-terminated UTF-8 decimal strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_encrypt_amount_token(
    amount: *const c_char,
    token: *const c_char,
    shared_secret: *const c_char,
    ephemeral_key_x: *const c_char,
    ephemeral_key_y: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let read = |ptr| unsafe { str_in(ptr) };
        let (Ok(amount), Ok(token), Ok(secret), Ok(ex), Ok(ey)) = (
            read(amount),
            read(token),
            read(shared_secret),
            read(ephemeral_key_x),
            read(ephemeral_key_y),
        ) else {
            return CurvyStatus::InvalidArgument;
        };
        let out_values = encrypt_amount_token(
            fr_from_dec(amount),
            fr_from_dec(token),
            &dec_to_biguint(secret),
            (&dec_to_biguint(ex), &dec_to_biguint(ey)),
        );
        str_vec_out(
            vec![
                fr_to_dec(&out_values.encrypted_amount),
                fr_to_dec(&out_values.encrypted_token),
            ],
            out,
        )
    })
}

/// Maps `(encryptedAmount, encryptedToken)` to `[amount, token]`.
///
/// # Safety
/// All pointers must be NUL-terminated UTF-8 decimal strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_decrypt_amount_token(
    encrypted_amount: *const c_char,
    encrypted_token: *const c_char,
    shared_secret: *const c_char,
    ephemeral_key_x: *const c_char,
    ephemeral_key_y: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let read = |ptr| unsafe { str_in(ptr) };
        let (Ok(amount), Ok(token), Ok(secret), Ok(ex), Ok(ey)) = (
            read(encrypted_amount),
            read(encrypted_token),
            read(shared_secret),
            read(ephemeral_key_x),
            read(ephemeral_key_y),
        ) else {
            return CurvyStatus::InvalidArgument;
        };
        let (amount, token) = decrypt_amount_token(
            fr_from_dec(amount),
            fr_from_dec(token),
            &dec_to_biguint(secret),
            (&dec_to_biguint(ex), &dec_to_biguint(ey)),
        );
        str_vec_out(vec![fr_to_dec(&amount), fr_to_dec(&token)], out)
    })
}

// Stealth addressing

/// Fresh random meta-keys `[k, v, K, V]`.
#[unsafe(no_mangle)]
pub extern "C" fn curvy_new_meta(out: *mut *mut c_char) -> CurvyStatus {
    guard_result(
        || {
            let (k, v, big_k, big_v) = stealth::new_meta().map_err(|e| e.to_string())?;
            Ok(vec![k, v, big_k, big_v])
        },
        |values| str_vec_out(values, out),
    )
}

/// Public meta-keys `[k, v, K, V]` for the given private spend/view keys.
///
/// # Safety
/// Both pointers must be NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_get_meta(
    k: *const c_char,
    v: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard_result(
        || {
            let (k, v) = unsafe { (str_in(k), str_in(v)) };
            let k = k.map_err(|_| "invalid spend key".to_string())?;
            let v = v.map_err(|_| "invalid view key".to_string())?;
            let (big_k, big_v) = stealth::get_meta(k, v).map_err(|e| e.to_string())?;
            Ok(vec![k.to_string(), v.to_string(), big_k, big_v])
        },
        |values| str_vec_out(values, out),
    )
}

/// Announces a payment to `(K, V)` as `[r, R, viewTag, spendingPubKey]`.
///
/// # Safety
/// Both pointers must be NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_send(
    big_k: *const c_char,
    big_v: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard_result(
        || {
            let (big_k, big_v) = unsafe { (str_in(big_k), str_in(big_v)) };
            let big_k = big_k.map_err(|_| "invalid spend pub key".to_string())?;
            let big_v = big_v.map_err(|_| "invalid view pub key".to_string())?;
            let (r, out) = stealth::send(big_k, big_v).map_err(|e| e.to_string())?;
            Ok(vec![r, out.big_r, out.view_tag, out.spending_pub_key])
        },
        |values| str_vec_out(values, out),
    )
}

/// Returns `[index, spendingPubKey, spendingPrivKey, ...]`.
///
/// Matches are candidates because the one-byte view tag admits false positives.
///
/// # Safety
/// `k`/`v` must be NUL-terminated strings; `rs_json`/`view_tags_json` must be
/// NUL-terminated JSON arrays of strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_scan(
    k: *const c_char,
    v: *const c_char,
    rs_json: *const c_char,
    view_tags_json: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard_result(
        || {
            let (k, v) = unsafe { (str_in(k), str_in(v)) };
            let k = k.map_err(|_| "invalid spend key".to_string())?;
            let v = v.map_err(|_| "invalid view key".to_string())?;
            let rs = unsafe { str_vec_in(rs_json) }.map_err(|_| "invalid rs array".to_string())?;
            let view_tags = unsafe { str_vec_in(view_tags_json) }
                .map_err(|_| "invalid viewTags array".to_string())?;
            let matches = stealth::scan(k, v, &rs, &view_tags).map_err(|e| e.to_string())?;
            let mut flat = Vec::with_capacity(matches.len() * 3);
            for found in matches {
                flat.push(found.index.to_string());
                flat.push(found.spending_pub_key);
                flat.push(found.spending_priv_key);
            }
            Ok(flat)
        },
        |values| str_vec_out(values, out),
    )
}

/// Returns `[index, spendingPubKey, ...]` for view-only scanning.
///
/// # Safety
/// See [`curvy_scan`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_viewer_scan(
    v: *const c_char,
    big_k: *const c_char,
    rs_json: *const c_char,
    view_tags_json: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard_result(
        || {
            let (v, big_k) = unsafe { (str_in(v), str_in(big_k)) };
            let v = v.map_err(|_| "invalid view key".to_string())?;
            let big_k = big_k.map_err(|_| "invalid spend pub key".to_string())?;
            let rs = unsafe { str_vec_in(rs_json) }.map_err(|_| "invalid rs array".to_string())?;
            let view_tags = unsafe { str_vec_in(view_tags_json) }
                .map_err(|_| "invalid viewTags array".to_string())?;
            let matches =
                stealth::viewer_scan(v, big_k, &rs, &view_tags).map_err(|e| e.to_string())?;
            let mut flat = Vec::with_capacity(matches.len() * 2);
            for found in matches {
                flat.push(found.index.to_string());
                flat.push(found.spending_pub_key);
            }
            Ok(flat)
        },
        |values| str_vec_out(values, out),
    )
}

/// # Safety
/// `point` must be a NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_is_valid_bn254_point(point: *const c_char) -> c_int {
    guard_bool(|| {
        unsafe { str_in(point) }
            .map(stealth::is_valid_bn254_point)
            .unwrap_or(false)
    })
}

/// # Safety
/// `point` must be a NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_is_valid_secp256k1_point(point: *const c_char) -> c_int {
    guard_bool(|| {
        unsafe { str_in(point) }
            .map(stealth::is_valid_secp256k1_point)
            .unwrap_or(false)
    })
}

/// Converts predicate errors and panics to false.
fn guard_bool(body: impl FnOnce() -> bool) -> c_int {
    let mut valid = false;
    let _ = guard(|| {
        valid = body();
        CurvyStatus::Ok
    });
    c_int::from(valid)
}
