//! Retained `ProofWorkspace` (and `WitnessWorkspace`) buffers must be zeroized,
//! not merely emptied.
//!
//! `Vec::clear` would also leave a workspace empty with its capacity intact, so
//! the in-crate tests cannot tell the two apart, and the crate forbids the
//! `unsafe` needed to look at spare capacity. This test binary installs a
//! recording allocator instead: every allocation made on the test thread while
//! recording is on is remembered until it is freed, and the test reads the bytes
//! of whatever is still live after each outcome. Those allocations are exactly
//! the workspaces' retained buffers, and every byte of them must be zero.
#![cfg(feature = "scratch")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ark_bn254::Fr;
use curvy_prover::{ProofWorkspace, Prover, ProverError, ResidentProver};
use curvy_witness::{WitnessWorkspace, wire};
use sha2::{Digest, Sha256};

const ZKEY: &[u8] = include_bytes!("../testdata/multiplier.zkey");
const ZKEY_SHA256: &str = "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f";
const INPUT: &str = r#"{"a":"3","b":"11"}"#;
const LIMIT: usize = 1024 * 1024;

const SLOTS: usize = 256;
static ADDRESSES: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static SIZES: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static LIVE: AtomicUsize = AtomicUsize::new(0);
static OVERFLOWED: AtomicBool = AtomicBool::new(false);

thread_local! {
    static RECORDING: Cell<bool> = const { Cell::new(false) };
}

struct Recording;

// SAFETY: every method forwards to `System` with the caller's arguments; the
// bookkeeping only stores addresses in fixed static arrays and never allocates.
unsafe impl GlobalAlloc for Recording {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        let pointer = unsafe { System.alloc(layout) };
        remember(pointer, layout.size());
        pointer
    }

    // Zero-initialized allocations are never recorded. Workspace buffers are
    // never allocated this way, and if one ever were, the exact retained-bytes
    // comparison would fail rather than skip it. Rayon is what this excludes: a
    // thread that injects a job into the global pool allocates the injector's
    // next queue block (job pointers, no witness data) with `alloc_zeroed`, and
    // that block outlives the call that happened to fill the previous one.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        forget(pointer);
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        // Only a recorded allocation stays recorded when it moves, so a buffer
        // that existed before recording began is never attributed to the test.
        if !moved.is_null() && forget(pointer) {
            remember(moved, new_size);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Recording = Recording;

fn recording() -> bool {
    RECORDING.try_with(Cell::get).unwrap_or(false)
}

fn set_recording(on: bool) {
    RECORDING.with(|recording| recording.set(on));
}

fn remember(pointer: *mut u8, size: usize) {
    if pointer.is_null() || !recording() {
        return;
    }
    let address = pointer.expose_provenance();
    for (slot, slot_size) in ADDRESSES.iter().zip(&SIZES) {
        if slot
            .compare_exchange(0, address, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            slot_size.store(size, Ordering::Release);
            LIVE.fetch_add(1, Ordering::AcqRel);
            return;
        }
    }
    OVERFLOWED.store(true, Ordering::Release);
}

/// Stop tracking an allocation; returns whether it was being tracked.
fn forget(pointer: *mut u8) -> bool {
    if LIVE.load(Ordering::Acquire) == 0 {
        return false;
    }
    let address = pointer.addr();
    for slot in &ADDRESSES {
        if slot
            .compare_exchange(address, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            LIVE.fetch_sub(1, Ordering::AcqRel);
            return true;
        }
    }
    false
}

/// Every live recorded allocation is a retained workspace buffer, and all of its
/// bytes - length and spare capacity alike - are zero.
fn assert_retained_buffers_are_zero(retained_bytes: usize, outcome: &str) {
    set_recording(false);
    assert!(
        !OVERFLOWED.load(Ordering::Acquire),
        "recording table overflowed"
    );
    let live = ADDRESSES
        .iter()
        .zip(&SIZES)
        .map(|(address, size)| {
            (
                address.load(Ordering::Acquire),
                size.load(Ordering::Acquire),
            )
        })
        .filter(|(address, _)| *address != 0)
        .collect::<Vec<_>>();
    let bytes = live.iter().map(|(_, size)| size).sum::<usize>();
    assert!(
        bytes > 0,
        "{outcome}: the workspaces retained nothing to check"
    );
    assert_eq!(
        bytes, retained_bytes,
        "{outcome}: live allocations other than the retained buffers: {live:x?}"
    );
    for (address, size) in live {
        // SAFETY: the address came from `System` and is still live: it was never
        // passed to `dealloc`, and the workspaces that own it are borrowed by the
        // caller, so nothing frees or writes it while it is read. `Vec::zeroize`
        // writes every byte of the capacity, so a correct workspace leaves it
        // initialized.
        let contents: &[u8] =
            unsafe { std::slice::from_raw_parts(std::ptr::with_exposed_provenance(address), size) };
        assert!(
            contents.iter().all(|byte| *byte == 0),
            "{outcome}: a retained {size}-byte buffer still holds witness or proof data"
        );
    }
    set_recording(true);
}

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF29CE484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3)
    })
}

/// The multiplier graph's shape with a chosen operation. With `ADD` its witness
/// has the right size but does not satisfy the key's constraint, so proving
/// fills every buffer and then fails self-verification.
fn graph(operation: u8) -> (Vec<u8>, String) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(wire::MAGIC);
    bytes.extend_from_slice(&wire::FORMAT_VERSION_V1.to_le_bytes());
    bytes.extend_from_slice(&wire::FIELD_BN254_FR.to_le_bytes());
    bytes.extend_from_slice(&wire::HEADER_SIZE.to_le_bytes());
    bytes.extend_from_slice(&[0; 32]);
    for count in [4_u32, 4, 2, 3] {
        bytes.extend_from_slice(&count.to_le_bytes());
    }
    for input in [0_u32, 1, 2] {
        bytes.push(0);
        bytes.extend_from_slice(&input.to_le_bytes());
    }
    bytes.extend_from_slice(&[2, operation]);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    for output in [0_u32, 3, 1, 2] {
        bytes.extend_from_slice(&output.to_le_bytes());
    }
    for (name, signal) in [("a", 1_u32), ("b", 2)] {
        bytes.extend_from_slice(&fnv1a(name).to_le_bytes());
        bytes.extend_from_slice(&signal.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
    }
    let pin = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    (bytes, pin)
}

#[test]
fn retained_proof_buffers_are_zeroized_after_success_and_error() {
    let resident = |operation| {
        let (bytes, pin) = graph(operation);
        ResidentProver::from_artifacts(ZKEY, ZKEY_SHA256, &bytes, &pin).expect("fixtures load")
    };
    let honest = resident(wire::MUL);
    let dishonest = resident(wire::ADD);
    // Anything a prover initializes lazily on first use is allocated before
    // recording.
    for prover in [&honest, &dishonest] {
        let _ = prover.prove_json_with_workspace(
            INPUT,
            &mut WitnessWorkspace::new(LIMIT),
            &mut ProofWorkspace::new(LIMIT),
        );
    }

    // Each outcome starts from empty workspaces kept well under their retention
    // limits, so everything they allocated stays retained and is inspected.
    for (outcome, prover) in [
        ("success", &honest),
        ("self-verification error", &dishonest),
    ] {
        set_recording(true);
        let mut witness = WitnessWorkspace::new(LIMIT);
        let mut proof = ProofWorkspace::new(LIMIT);
        for _ in 0..2 {
            let result = prover.prove_json_with_workspace(INPUT, &mut witness, &mut proof);
            match outcome {
                "success" => assert!(result.is_ok()),
                _ => assert!(matches!(result, Err(ProverError::SelfVerificationFailed))),
            }
            drop(result);
            assert!(proof.retained_bytes() > 0 && witness.retained_bytes() > 0);
            assert_retained_buffers_are_zero(
                witness.retained_bytes() + proof.retained_bytes(),
                outcome,
            );
        }
        drop((witness, proof));
        set_recording(false);
        assert_eq!(
            LIVE.load(Ordering::Acquire),
            0,
            "buffers outlived the workspaces"
        );
    }

    // The direct entry point, followed by an error on the reused workspace.
    let prover = Prover::from_zkey_bytes(ZKEY, ZKEY_SHA256).expect("fixture key");
    let assignment = [Fr::from(1), Fr::from(33), Fr::from(3), Fr::from(11)];
    set_recording(true);
    let mut proof = ProofWorkspace::new(LIMIT);
    prover
        .prove_with_workspace(&assignment, &mut proof)
        .expect("direct proof");
    assert_retained_buffers_are_zero(proof.retained_bytes(), "direct success");
    let mut invalid = assignment;
    invalid[0] = Fr::from(0);
    assert!(matches!(
        prover.prove_with_workspace(&invalid, &mut proof),
        Err(ProverError::AssignmentConstant)
    ));
    assert_retained_buffers_are_zero(proof.retained_bytes(), "direct error");
    drop(proof);
    set_recording(false);
}
