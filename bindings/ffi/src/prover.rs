//! C ABI for witness evaluation and Groth16 proving.
//!
//! Calls are synchronous; hosts should run expensive proving work off the UI
//! thread. Constructors authenticate artifacts against the supplied SHA-256.

use std::ffi::c_char;

use curvy_prover::{CircuitProver, Prover};
use curvy_witness::WitnessGraph;

use crate::abi::{CurvyStatus, bytes_in, guard, set_last_error, str_in, string_out};
use crate::registry::Registry;

static GRAPHS: Registry<WitnessGraph> = Registry::new();
static PROVERS: Registry<Prover> = Registry::new();
static CIRCUIT_PROVERS: Registry<CircuitProver> = Registry::new();

fn handle_out(handle: u64, out: *mut u64) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    unsafe { *out = handle };
    CurvyStatus::Ok
}

fn usize_out(value: usize, out: *mut u32) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    unsafe { *out = value as u32 };
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
pub extern "C" fn curvy_witness_graph_free(handle: u64) {
    GRAPHS.remove(handle);
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
pub extern "C" fn curvy_prover_free(handle: u64) {
    PROVERS.remove(handle);
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

// CircuitProver

/// # Safety
/// Both buffer pointers must describe readable regions; both sha256 pointers
/// must be NUL-terminated 64-character hex strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_circuit_prover_new(
    zkey: *const u8,
    zkey_len: usize,
    expected_zkey_sha256: *const c_char,
    graph: *const u8,
    graph_len: usize,
    expected_graph_sha256: *const c_char,
    out: *mut u64,
) -> CurvyStatus {
    construct(
        &CIRCUIT_PROVERS,
        || {
            let zkey_bytes = unsafe { bytes_in(zkey, zkey_len) }
                .map_err(|_| "invalid zkey buffer".to_string())?;
            let graph_bytes = unsafe { bytes_in(graph, graph_len) }
                .map_err(|_| "invalid graph buffer".to_string())?;
            let zkey_hash = unsafe { str_in(expected_zkey_sha256) }
                .map_err(|_| "invalid expected zkey sha256".to_string())?;
            let graph_hash = unsafe { str_in(expected_graph_sha256) }
                .map_err(|_| "invalid expected graph sha256".to_string())?;
            CircuitProver::from_artifacts(zkey_bytes, zkey_hash, graph_bytes, graph_hash)
                .map_err(|e| e.to_string())
        },
        out,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_circuit_prover_free(handle: u64) {
    CIRCUIT_PROVERS.remove(handle);
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_circuit_prover_num_constraints(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &CIRCUIT_PROVERS,
        handle,
        |prover| Ok(prover.num_constraints()),
        |value| usize_out(value, out),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn curvy_circuit_prover_num_public(handle: u64, out: *mut u32) -> CurvyStatus {
    with_handle(
        &CIRCUIT_PROVERS,
        handle,
        |prover| Ok(prover.num_public()),
        |value| usize_out(value, out),
    )
}

/// Calculates, proves, and self-verifies without exporting the witness.
///
/// # Safety
/// `input_json` must be a NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_circuit_prover_prove(
    handle: u64,
    input_json: *const c_char,
    out: *mut *mut c_char,
) -> CurvyStatus {
    with_handle(
        &CIRCUIT_PROVERS,
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
