use std::ffi::c_char;

use curvy_core::{
    eddsa::{ScalarSigningKey, Signature, ephemeral_pub_key_bytes},
    encoding::try_dec_to_u256,
    field::{Bn254Fr, fr_to_dec},
    witness::{NoteSigner, SeedNoteSigner},
};
use zeroize::Zeroizing;

use crate::{
    abi::{
        CurvyStatus, bytes_in, free_status, guard, null_output, set_last_error, str_in, str_vec_out,
    },
    registry::Registry,
};

static SEED_SIGNERS: Registry<Option<Box<SeedNoteSigner>>> = Registry::new();
static SCALAR_SIGNERS: Registry<Option<Box<ScalarSigningKey>>> = Registry::new();

unsafe fn key_bytes(input: *const u8, len: usize) -> Result<Zeroizing<[u8; 32]>, CurvyStatus> {
    if len != 32 {
        set_last_error("key must contain exactly 32 bytes");
        return Err(CurvyStatus::InvalidArgument);
    }
    let input = unsafe { bytes_in(input, len) }?;
    let mut bytes = Zeroizing::new([0_u8; 32]);
    bytes.copy_from_slice(input);
    Ok(bytes)
}

fn invalid(error: impl std::fmt::Display) -> CurvyStatus {
    set_last_error(error.to_string());
    CurvyStatus::InvalidArgument
}

fn unknown_handle() -> CurvyStatus {
    set_last_error("unknown or freed signer handle");
    CurvyStatus::InvalidHandle
}

fn signature_out(signature: Signature, out: *mut *mut c_char) -> CurvyStatus {
    str_vec_out(
        vec![
            fr_to_dec(&signature.r8.0),
            fr_to_dec(&signature.r8.1),
            signature.s.to_string(),
        ],
        out,
    )
}

/// Imports a 32-byte seed. The caller owns the input and may wipe it after return.
/// # Safety
/// `seed` is readable for `len` bytes; `out` points to writable handle storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_seed_signer_new(
    seed: *const u8,
    len: usize,
    out: *mut u64,
) -> CurvyStatus {
    guard(|| {
        if out.is_null() {
            return null_output();
        }
        let bytes = match unsafe { key_bytes(seed, len) } {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        let key = Box::new(SeedNoteSigner::from_bytes(*bytes));
        let handle = SEED_SIGNERS.insert(Some(key));
        unsafe { std::ptr::write_unaligned(out, handle) };
        CurvyStatus::Ok
    })
}

/// Imports a canonical nonzero 32-byte little-endian scalar.
/// The caller owns the input and may wipe it after return.
/// # Safety
/// `scalar` is readable for `len` bytes; `out` points to writable handle storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_scalar_signer_new(
    scalar: *const u8,
    len: usize,
    out: *mut u64,
) -> CurvyStatus {
    guard(|| {
        if out.is_null() {
            return null_output();
        }
        let bytes = match unsafe { key_bytes(scalar, len) } {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        let key = match ScalarSigningKey::from_le_bytes(*bytes) {
            Ok(key) => Box::new(key),
            Err(error) => return invalid(error),
        };
        let handle = SCALAR_SIGNERS.insert(Some(key));
        unsafe { std::ptr::write_unaligned(out, handle) };
        CurvyStatus::Ok
    })
}

/// Erases and frees an owned seed signer after its active operation completes.
#[unsafe(no_mangle)]
pub extern "C" fn curvy_seed_signer_free(handle: u64) -> CurvyStatus {
    guard(|| free_status(SEED_SIGNERS.remove_with(handle, |key| drop(key.take()))))
}

/// Erases and frees an owned scalar signer after its active operation completes.
#[unsafe(no_mangle)]
pub extern "C" fn curvy_scalar_signer_free(handle: u64) -> CurvyStatus {
    guard(|| free_status(SCALAR_SIGNERS.remove_with(handle, |key| drop(key.take()))))
}

/// Returns `[x, y]` as a JSON array of decimal strings.
/// # Safety
/// `out` points to writable string-pointer storage. Free output with `curvy_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_seed_signer_public_key(
    handle: u64,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        match SEED_SIGNERS.with(handle, |key| {
            let Some(key) = key.as_ref() else {
                return unknown_handle();
            };
            let (x, y) = key.public_key();
            str_vec_out(vec![fr_to_dec(&x), fr_to_dec(&y)], out)
        }) {
            Some(status) => status,
            None => unknown_handle(),
        }
    })
}

/// Returns `[x, y]` as a JSON array of decimal strings.
/// # Safety
/// `out` points to writable string-pointer storage. Free output with `curvy_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_scalar_signer_public_key(
    handle: u64,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        match SCALAR_SIGNERS.with(handle, |key| {
            let Some(key) = key.as_ref() else {
                return unknown_handle();
            };
            let public = key.verifying_key();
            str_vec_out(vec![fr_to_dec(&public.x()), fr_to_dec(&public.y())], out)
        }) {
            Some(status) => status,
            None => unknown_handle(),
        }
    })
}

/// Signs an unsigned decimal message below `2^256`, returning `[R8.x, R8.y, S]` as JSON.
/// # Safety
/// `message` is NUL-terminated UTF-8; `out` is writable string-pointer storage.
/// Free output with `curvy_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_seed_signer_sign(
    handle: u64,
    message: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let message = match unsafe { str_in(message) } {
            Ok(message) => message,
            Err(status) => return status,
        };
        let message = match try_dec_to_u256(message) {
            Ok(message) => message,
            Err(error) => return invalid(error),
        };
        match SEED_SIGNERS.with(handle, |key| match key.as_ref() {
            Some(key) => signature_out(key.sign_raw(&message), out),
            None => unknown_handle(),
        }) {
            Some(status) => status,
            None => unknown_handle(),
        }
    })
}

/// Signs a canonical decimal BN254 field message, returning `[R8.x, R8.y, S]` as JSON.
/// # Safety
/// `message` is NUL-terminated UTF-8; `out` is writable string-pointer storage.
/// Free output with `curvy_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_scalar_signer_sign(
    handle: u64,
    message: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let message = match unsafe { str_in(message) } {
            Ok(message) => message,
            Err(status) => return status,
        };
        let message = match Bn254Fr::try_from_dec(message) {
            Ok(message) => message,
            Err(error) => return invalid(error),
        };
        match SCALAR_SIGNERS.with(handle, |key| {
            let Some(key) = key.as_ref() else {
                return unknown_handle();
            };
            match key.sign_curvy_v1(message) {
                Ok(signature) => signature_out(signature.to_signature(), out),
                Err(error) => {
                    set_last_error(error.to_string());
                    CurvyStatus::Error
                }
            }
        }) {
            Some(status) => status,
            None => unknown_handle(),
        }
    })
}

/// Returns `[x, y]` for a raw 32-byte little-endian scalar, including zero.
/// # Safety
/// `scalar` is readable for `len` bytes; `out` is writable string-pointer storage.
/// Free output with `curvy_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_ephemeral_pub_key_bytes(
    scalar: *const u8,
    len: usize,
    out: *mut *mut c_char,
) -> CurvyStatus {
    guard(|| {
        let bytes = match unsafe { key_bytes(scalar, len) } {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        let (x, y) = ephemeral_pub_key_bytes(&bytes);
        str_vec_out(vec![fr_to_dec(&x), fr_to_dec(&y)], out)
    })
}
