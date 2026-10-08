//! A retained `WitnessWorkspace` must be zeroized, not merely emptied.
//!
//! `Vec::clear` would also leave the workspace empty with its capacity intact, so
//! the crate's own tests cannot tell the two apart, and the crate forbids the
//! `unsafe` needed to look at spare capacity. This test binary installs a
//! recording allocator instead: every allocation made on the test thread while
//! recording is on is remembered until it is freed, and the test reads the bytes
//! of whatever is still live after each outcome. Those allocations are exactly
//! the workspace's retained buffers, and every byte of them must be zero.
//!
//! Keep this binary to one `#[test]`: it briefly replaces the global panic hook.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ark_bn254::Fr;
use curvy_witness::{WitnessError, WitnessGraph, WitnessWorkspace, wire};
use sha2::{Digest, Sha256};

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

/// Recorded allocations that are still live. Call with recording off.
fn live_allocations() -> Vec<(usize, usize)> {
    assert!(!recording());
    assert!(
        !OVERFLOWED.load(Ordering::Acquire),
        "recording table overflowed"
    );
    ADDRESSES
        .iter()
        .zip(&SIZES)
        .map(|(address, size)| {
            (
                address.load(Ordering::Acquire),
                size.load(Ordering::Acquire),
            )
        })
        .filter(|(address, _)| *address != 0)
        .collect()
}

/// Every live recorded allocation is a retained workspace buffer, and all of its
/// bytes - length and spare capacity alike - are zero.
fn assert_retained_buffers_are_zero(workspace: &WitnessWorkspace, name: &str, outcome: &str) {
    set_recording(false);
    let live = live_allocations();
    let bytes = live.iter().map(|(_, size)| size).sum::<usize>();
    assert!(
        bytes > 0,
        "{name} {outcome}: the workspace retained nothing to check"
    );
    assert_eq!(
        bytes,
        workspace.retained_bytes(),
        "{name} {outcome}: live allocations other than the retained buffers"
    );
    for (address, size) in live {
        // SAFETY: the address came from `System` and is still live: it was never
        // passed to `dealloc`, and the workspace that owns it is borrowed here, so
        // nothing frees or writes it while it is read. `Vec::zeroize` writes every
        // byte of the capacity, so a correct workspace leaves it initialized.
        let contents: &[u8] =
            unsafe { std::slice::from_raw_parts(std::ptr::with_exposed_provenance(address), size) };
        assert!(
            contents.iter().all(|byte| *byte == 0),
            "{name} {outcome}: a retained {size}-byte buffer still holds witness data"
        );
    }
    set_recording(true);
}

fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xCBF29CE484222325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001B3)
    })
}

/// SIGNET v1: inputs `a` and `b`, outputs `[1, a / b, a * b, a, b]`. The division
/// fails after the inputs and product are already in the value buffer.
fn graph_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(wire::MAGIC);
    bytes.extend_from_slice(&wire::FORMAT_VERSION_V1.to_le_bytes());
    bytes.extend_from_slice(&wire::FIELD_BN254_FR.to_le_bytes());
    bytes.extend_from_slice(&wire::HEADER_SIZE.to_le_bytes());
    bytes.extend_from_slice(&[0; 32]);
    for count in [5_u32, 5, 2, 3] {
        bytes.extend_from_slice(&count.to_le_bytes());
    }
    for input in [0_u32, 1, 2] {
        bytes.push(0);
        bytes.extend_from_slice(&input.to_le_bytes());
    }
    for operation in [wire::MUL, wire::DIV] {
        bytes.extend_from_slice(&[2, operation]);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
    }
    for output in [0_u32, 4, 3, 1, 2] {
        bytes.extend_from_slice(&output.to_le_bytes());
    }
    for (name, signal) in [("a", 1_u32), ("b", 2)] {
        bytes.extend_from_slice(&fnv1a(name).to_le_bytes());
        bytes.extend_from_slice(&signal.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
    }
    bytes
}

const SECRET: &str = r#"{"a":"123456789012345678901234567890","b":"987654321098765"}"#;
const DIVIDES_BY_ZERO: &str = r#"{"a":"123456789012345678901234567890","b":"0"}"#;

trait Evaluator {
    fn run(
        &self,
        input: &str,
        workspace: &mut WitnessWorkspace,
        consume: &mut dyn FnMut(&[Fr]),
    ) -> Result<(), WitnessError>;
}
impl Evaluator for WitnessGraph {
    fn run(
        &self,
        input: &str,
        workspace: &mut WitnessWorkspace,
        consume: &mut dyn FnMut(&[Fr]),
    ) -> Result<(), WitnessError> {
        self.with_witness_json(input, workspace, consume)
    }
}
#[cfg(feature = "sage")]
impl Evaluator for curvy_witness::sage::SageGraph {
    fn run(
        &self,
        input: &str,
        workspace: &mut WitnessWorkspace,
        consume: &mut dyn FnMut(&[Fr]),
    ) -> Result<(), WitnessError> {
        self.with_witness_json(input, workspace, consume)
    }
}

/// Each outcome starts from an empty workspace kept well under its retention
/// limit, so everything it allocated stays retained and is inspected.
fn check(name: &str, evaluator: &dyn Evaluator) {
    const LIMIT: usize = 1024 * 1024;

    set_recording(true);
    let mut workspace = WitnessWorkspace::new(LIMIT);
    let mut width = 0;
    evaluator
        .run(SECRET, &mut workspace, &mut |assignment| {
            assert!(assignment[1..].iter().all(|value| *value != Fr::from(0)));
            width = assignment.len();
        })
        .expect("secret input evaluates");
    assert_eq!(width, 5);
    assert_retained_buffers_are_zero(&workspace, name, "success");
    // Reuse keeps the same buffers and still leaves them zeroed.
    evaluator
        .run(SECRET, &mut workspace, &mut |_| {})
        .expect("secret input evaluates again");
    assert_retained_buffers_are_zero(&workspace, name, "reuse");
    drop(workspace);
    assert_eq!(
        LIVE.load(Ordering::Acquire),
        0,
        "{name}: buffers outlived the workspace"
    );

    let mut workspace = WitnessWorkspace::new(LIMIT);
    // The default hook would print, and the test harness keeps captured output
    // in a growing buffer allocated on this thread. Swap hooks while not
    // recording so neither box is mistaken for a workspace buffer.
    set_recording(false);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    set_recording(true);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        evaluator.run(SECRET, &mut workspace, &mut |_| panic!("consumer failed"))
    }));
    set_recording(false);
    std::panic::set_hook(hook);
    set_recording(true);
    assert!(unwound.is_err());
    drop(unwound);
    assert_retained_buffers_are_zero(&workspace, name, "panic");
    drop(workspace);

    let mut workspace = WitnessWorkspace::new(LIMIT);
    let error = evaluator
        .run(DIVIDES_BY_ZERO, &mut workspace, &mut |_| {
            unreachable!("evaluation must fail")
        })
        .expect_err("division by zero");
    assert!(
        matches!(error, WitnessError::DivisionByZero(4)),
        "{error:?}"
    );
    drop(error);
    assert_retained_buffers_are_zero(&workspace, name, "error");
    drop(workspace);
    set_recording(false);
}

#[test]
fn retained_buffers_are_zeroized_after_success_error_and_panic() {
    let bytes = graph_bytes();
    let pin = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let graph = WitnessGraph::from_bytes(&bytes, &pin).expect("synthetic graph parses");
    #[cfg(feature = "sage")]
    let sage = curvy_witness::sage::SageGraph::from_bytes(&bytes, &pin).expect("SAGE compiles");
    check("WitnessGraph", &graph);
    #[cfg(feature = "sage")]
    check("SageGraph", &sage);
}
