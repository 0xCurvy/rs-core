//! C ABI for witness evaluation and Groth16 proving.
//!
//! Calls are synchronous; hosts should run expensive proving work off the UI
//! thread. Constructors authenticate artifacts against the supplied SHA-256.

use std::ffi::c_char;

use curvy_prover::{Prover, ResidentProver};
use curvy_witness::{Limits, WitnessGraph, sage::SageGraph};

use crate::abi::{
    CurvyBytes, CurvyStatus, bytes_in, bytes_out, guard, set_last_error, str_in, string_out,
};
use crate::registry::Registry;

static GRAPHS: Registry<WitnessGraph> = Registry::new();
static PROVERS: Registry<Prover> = Registry::new();
static RESIDENT_PROVERS: Registry<ResidentProver> = Registry::new();

fn handle_out(handle: u64, out: *mut u64) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    unsafe { std::ptr::write_unaligned(out, handle) };
    CurvyStatus::Ok
}

fn usize_out(value: usize, out: *mut u32) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    unsafe { std::ptr::write_unaligned(out, value as u32) };
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

/// Builds the snarkjs-compatible proof response.
fn bundle_json(bundle: &curvy_prover::ProofBundle) -> String {
    format!(
        "{{\"proof\":{},\"publicSignals\":{}}}",
        bundle.proof_json, bundle.public_signals_json
    )
}

// WitnessGraph

/// Selects client limits when false and batch-prover limits when true.
///
/// # Safety
/// `graph`/`len` must describe a readable region; `expected_sha256` must be a
/// NUL-terminated 64-character hex string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_witness_graph_new(
    graph: *const u8,
    len: usize,
    expected_sha256: *const c_char,
    batch_profile: bool,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &GRAPHS,
        || {
            let bytes =
                unsafe { bytes_in(graph, len) }.map_err(|_| "invalid graph buffer".to_string())?;
            let expected = unsafe { str_in(expected_sha256) }
                .map_err(|_| "invalid expected graph sha256".to_string())?;
            let limits = if batch_profile {
                curvy_witness::Limits::batch_prover()
            } else {
                curvy_witness::Limits::client()
            };
            WitnessGraph::from_bytes_with_limits(bytes, expected, limits).map_err(|e| e.to_string())
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_witness_graph_free(handle: u64) -> CurvyStatus {
    crate::abi::guard(|| {
        if GRAPHS.remove(handle) {
            CurvyStatus::Ok
        } else {
            crate::abi::set_last_error("invalid, freed, or wrong-type handle");
            CurvyStatus::InvalidArgument
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_witness_graph_assignment_size(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &GRAPHS,
        handle,
        |graph| Ok(graph.assignment_size()),
        |value| usize_out(value, out),
    )
}

/// Evaluate the graph and return the assignment as a JSON array of decimal
/// strings.
///
/// # Safety
/// `input_json` must be a NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_witness_graph_calculate(
    handle: u64,
    input_json: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    with_handle(
        &GRAPHS,
        handle,
        |graph| {
            let input =
                unsafe { str_in(input_json) }.map_err(|_| "invalid input json".to_string())?;
            let assignment = graph.calculate_json(input).map_err(|e| e.to_string())?;
            Ok(curvy_prover::publics_to_json(&assignment))
        },
        |json| string_out(json, out),
    )
}

/// Evaluate the graph and return concatenated canonical 32-byte big-endian
/// assignment field elements.
///
/// # Safety
/// `input_json` must be a NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_witness_graph_calculate_packed(
    handle: u64,
    input_json: *const c_char,
    out: *mut CurvyBytes,
) -> CurvyStatus {
    with_handle(
        &GRAPHS,
        handle,
        |graph| {
            let input =
                unsafe { str_in(input_json) }.map_err(|_| "invalid input json".to_string())?;
            let assignment = graph.calculate_json(input).map_err(|e| e.to_string())?;
            Ok(curvy_prover::assignment_to_packed_be(&assignment))
        },
        |packed| bytes_out(packed, out),
    )
}

// Prover for precomputed witnesses

/// # Safety
/// `zkey`/`len` must describe a readable region; `expected_sha256` must be a
/// NUL-terminated 64-character hex string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_prover_new(
    zkey: *const u8,
    len: usize,
    expected_sha256: *const c_char,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &PROVERS,
        || {
            let bytes =
                unsafe { bytes_in(zkey, len) }.map_err(|_| "invalid zkey buffer".to_string())?;
            let expected = unsafe { str_in(expected_sha256) }
                .map_err(|_| "invalid expected zkey sha256".to_string())?;
            Prover::from_zkey_bytes(bytes, expected).map_err(|e| e.to_string())
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_prover_free(handle: u64) -> CurvyStatus {
    crate::abi::guard(|| {
        if PROVERS.remove(handle) {
            CurvyStatus::Ok
        } else {
            crate::abi::set_last_error("invalid, freed, or wrong-type handle");
            CurvyStatus::InvalidArgument
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_prover_num_constraints(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &PROVERS,
        handle,
        |prover| Ok(prover.num_constraints()),
        |value| usize_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_prover_num_public(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &PROVERS,
        handle,
        |prover| Ok(prover.num_public()),
        |value| usize_out(value, out),
    )
}

/// Prove from a serialised `.wtns` witness.
///
/// # Safety
/// `wtns`/`len` must describe a readable region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_prover_prove(
    handle: u64,
    wtns: *const u8,
    len: usize,
    out: *mut *mut c_char,
) -> CurvyStatus {
    with_handle(
        &PROVERS,
        handle,
        |prover| {
            let bytes =
                unsafe { bytes_in(wtns, len) }.map_err(|_| "invalid wtns buffer".to_string())?;
            let bundle = prover.prove_wtns(bytes).map_err(|e| e.to_string())?;
            Ok(bundle_json(&bundle))
        },
        |json| string_out(json, out),
    )
}

// ResidentProver

/// # Safety
/// Both buffer pointers must describe readable regions; both sha256 pointers
/// must be NUL-terminated 64-character hex strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_resident_prover_new(
    zkey: *const u8,
    zkey_len: usize,
    expected_zkey_sha256: *const c_char,
    graph: *const u8,
    graph_len: usize,
    expected_graph_sha256: *const c_char,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &RESIDENT_PROVERS,
        || {
            let zkey_bytes = unsafe { bytes_in(zkey, zkey_len) }
                .map_err(|_| "invalid zkey buffer".to_string())?;
            let graph_bytes = unsafe { bytes_in(graph, graph_len) }
                .map_err(|_| "invalid graph buffer".to_string())?;
            let zkey_hash = unsafe { str_in(expected_zkey_sha256) }
                .map_err(|_| "invalid expected zkey sha256".to_string())?;
            let graph_hash = unsafe { str_in(expected_graph_sha256) }
                .map_err(|_| "invalid expected graph sha256".to_string())?;
            ResidentProver::from_artifacts(zkey_bytes, zkey_hash, graph_bytes, graph_hash)
                .map_err(|e| e.to_string())
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_resident_prover_free(handle: u64) -> CurvyStatus {
    crate::abi::guard(|| {
        if RESIDENT_PROVERS.remove(handle) {
            CurvyStatus::Ok
        } else {
            crate::abi::set_last_error("invalid, freed, or wrong-type handle");
            CurvyStatus::InvalidArgument
        }
    })
}

/// Compile an authenticated witness graph to SAGE for resident proving.
///
/// # Safety
/// Buffer pointers must describe readable regions; hashes must be NUL-terminated
/// hex strings. `out` must be writable. Client artifact limits apply.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_resident_prover_new_sage(
    zkey: *const u8,
    zkey_len: usize,
    expected_zkey_sha256: *const c_char,
    graph: *const u8,
    graph_len: usize,
    expected_graph_sha256: *const c_char,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &RESIDENT_PROVERS,
        || {
            let zkey = unsafe { bytes_in(zkey, zkey_len) }
                .map_err(|_| "invalid zkey buffer".to_string())?;
            let graph = unsafe { bytes_in(graph, graph_len) }
                .map_err(|_| "invalid graph buffer".to_string())?;
            let zkey_hash = unsafe { str_in(expected_zkey_sha256) }
                .map_err(|_| "invalid expected zkey sha256".to_string())?;
            let graph_hash = unsafe { str_in(expected_graph_sha256) }
                .map_err(|_| "invalid expected graph sha256".to_string())?;
            let prover = Prover::from_zkey_bytes(zkey, zkey_hash).map_err(|e| e.to_string())?;
            let sage = SageGraph::from_bytes(graph, graph_hash).map_err(|e| e.to_string())?;
            ResidentProver::with_sage(prover, sage).map_err(|e| e.to_string())
        },
        out,
    )
}

/// Load a compiled SAGE cache pinned independently from its source graph.
/// The original graph file is unnecessary, but its trusted digest is required.
///
/// # Safety
/// Buffer pointers must describe readable regions; all three hashes must be
/// NUL-terminated hex strings. `out` must be writable. Client limits apply.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_resident_prover_new_compiled_sage(
    zkey: *const u8,
    zkey_len: usize,
    expected_zkey_sha256: *const c_char,
    program: *const u8,
    program_len: usize,
    expected_program_sha256: *const c_char,
    expected_graph_sha256: *const c_char,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &RESIDENT_PROVERS,
        || {
            let zkey = unsafe { bytes_in(zkey, zkey_len) }
                .map_err(|_| "invalid zkey buffer".to_string())?;
            let program = unsafe { bytes_in(program, program_len) }
                .map_err(|_| "invalid program buffer".to_string())?;
            let zkey_hash = unsafe { str_in(expected_zkey_sha256) }
                .map_err(|_| "invalid expected zkey sha256".to_string())?;
            let program_hash = unsafe { str_in(expected_program_sha256) }
                .map_err(|_| "invalid expected program sha256".to_string())?;
            let graph_hash = unsafe { str_in(expected_graph_sha256) }
                .map_err(|_| "invalid expected graph sha256".to_string())?;
            let prover = Prover::from_zkey_bytes(zkey, zkey_hash).map_err(|e| e.to_string())?;
            ResidentProver::from_compiled_sage(
                prover,
                program,
                program_hash,
                graph_hash,
                Limits::client(),
            )
            .map_err(|e| e.to_string())
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_resident_prover_num_constraints(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &RESIDENT_PROVERS,
        handle,
        |prover| Ok(prover.num_constraints()),
        |value| usize_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_resident_prover_num_public(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &RESIDENT_PROVERS,
        handle,
        |prover| Ok(prover.num_public()),
        |value| usize_out(value, out),
    )
}

/// Returns the stable developer-facing mode string (`resident`).
///
/// # Safety
/// `out` must be writable and the returned string must be released with
/// `curvy_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_resident_prover_mode(
    handle: u64,
    out: *mut *mut c_char,
) -> CurvyStatus {
    with_handle(
        &RESIDENT_PROVERS,
        handle,
        |prover| Ok(prover.mode().as_str().to_owned()),
        |mode| string_out(mode, out),
    )
}

/// Returns the architecture profile string (`HAWK`).
///
/// # Safety
/// `out` must be writable and the returned string must be released with
/// `curvy_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_resident_prover_profile(
    handle: u64,
    out: *mut *mut c_char,
) -> CurvyStatus {
    with_handle(
        &RESIDENT_PROVERS,
        handle,
        |prover| Ok(prover.profile().to_owned()),
        |profile| string_out(profile, out),
    )
}

/// Returns the SHA-256 of the loaded key's verifying key as 64 lowercase hex
/// characters. Compare it against the deployed verifier before submitting
/// proofs; the zkey digest pins the artifact, this pins the verifier.
///
/// # Safety
/// `out` must be writable and the returned string must be released with
/// `curvy_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_resident_prover_verifying_key_digest(
    handle: u64,
    out: *mut *mut c_char,
) -> CurvyStatus {
    with_handle(
        &RESIDENT_PROVERS,
        handle,
        |prover| Ok(prover.verifying_key_digest()),
        |digest| string_out(digest, out),
    )
}

/// Calculates, proves, and self-verifies without exporting the witness.
///
/// # Safety
/// `input_json` must be a NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_resident_prover_prove(
    handle: u64,
    input_json: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    with_handle(
        &RESIDENT_PROVERS,
        handle,
        |prover| {
            let input =
                unsafe { str_in(input_json) }.map_err(|_| "invalid input json".to_string())?;
            let bundle = prover.prove_json(input).map_err(|e| e.to_string())?;
            Ok(bundle_json(&bundle))
        },
        |json| string_out(json, out),
    )
}
