//! C ABI marshalling and error handling.
//!
//! * Strings use NUL-terminated UTF-8. Free Rust outputs with [`curvy_string_free`].
//! * String arrays use one JSON array string.
//! * Byte buffers use `(ptr, len)`. Free Rust outputs with [`curvy_bytes_free`].
//! * Fallible calls return [`CurvyStatus`] and write through an out-pointer.
//!   Read the current thread's error with [`curvy_last_error`].
//!
//! Entry points catch panics so they never unwind into C.

use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString, c_char};
use std::fmt::Display;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

use zeroize::{Zeroize, Zeroizing};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CurvyStatus {
    Ok = 0,
    /// A Rust-side error; call `curvy_last_error` for the message.
    Error = 1,
    /// A null pointer, non-UTF-8 string, or malformed value arrived from the caller.
    InvalidArgument = 2,
    /// A handle was unknown, already freed, or of another object type.
    InvalidHandle = 3,
    /// Rust panicked; call `curvy_last_error`.
    Panic = 4,
}

/// An owned byte buffer handed to the caller. Free with [`curvy_bytes_free`].
#[repr(C)]
pub struct CurvyBytes {
    pub ptr: *mut u8,
    pub len: usize,
}

impl CurvyBytes {
    pub fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }

    /// Converts a vector to an exact-layout allocation for [`curvy_bytes_free`].
    ///
    /// Outputs can carry private tree data. Boxing a vector with spare capacity
    /// shrinks it in place or reallocates, which may free an unwiped copy, so
    /// such vectors are copied into an exact-size buffer and wiped instead.
    pub fn from_vec(mut vec: Vec<u8>) -> Self {
        if vec.len() != vec.capacity() {
            let exact = vec.as_slice().to_vec();
            vec.zeroize();
            vec = exact;
        }
        debug_assert_eq!(vec.len(), vec.capacity());
        let boxed = vec.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed).cast::<u8>();
        Self { ptr, len }
    }
}

// Hosts can call in from thread-local destructors (C++ `thread_local` RAII,
// Swift teardown) after these slots are destroyed. `LocalKey::with` panics then,
// outside any `catch_unwind`, so every access uses `try_with` and drops the
// message instead.
thread_local! {
    static GUARD_DEPTH: Cell<usize> = const { Cell::new(0) };
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn replace_last_error(message: Option<CString>) {
    let _ = LAST_ERROR.try_with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut() {
            *slot = message;
        }
    });
}

pub fn set_last_error(message: impl Into<String>) {
    let message = message.into();
    // A NUL inside an error message would truncate it; replace rather than drop.
    let sanitised = message.replace('\0', "\\0");
    replace_last_error(CString::new(sanitised).ok());
}

/// Returns this thread's last error, or null. Copy it before the next fallible call.
///
/// # Safety
/// The returned pointer is owned by Rust and must not be freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn curvy_last_error() -> *const c_char {
    LAST_ERROR
        .try_with(|slot| {
            slot.try_borrow()
                .ok()
                .and_then(|message| message.as_ref().map(|message| message.as_ptr()))
        })
        .ok()
        .flatten()
        .unwrap_or(std::ptr::null())
}

/// # Safety
/// `ptr` must have come from this library and not been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe { CString::from_raw(ptr) }
        .into_bytes_with_nul()
        .zeroize();
}

/// # Safety
/// `bytes` must have come from this library and not been freed already.
///
/// A zero length means no allocation was made.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_bytes_free(bytes: CurvyBytes) {
    if bytes.ptr.is_null() || bytes.len == 0 {
        return;
    }
    let mut owned =
        unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(bytes.ptr, bytes.len)) };
    owned.zeroize();
}

// Failures

/// Why a call body failed; selects the returned status.
pub enum Failure {
    /// Malformed caller input: a null or non-UTF-8 pointer, or a value that does
    /// not parse. Returns [`CurvyStatus::InvalidArgument`].
    Invalid(String),
    /// Well-formed input the core rejected, or an internal failure. Returns
    /// [`CurvyStatus::Error`].
    Error(String),
}

impl Failure {
    /// Records the message and returns the matching status.
    pub fn report(self) -> CurvyStatus {
        let (status, message) = match self {
            Self::Invalid(message) => (CurvyStatus::InvalidArgument, message),
            Self::Error(message) => (CurvyStatus::Error, message),
        };
        set_last_error(message);
        status
    }
}

/// A malformed caller input.
pub fn invalid(message: impl Display) -> Failure {
    Failure::Invalid(message.to_string())
}

/// A core rejection or internal failure.
pub fn failed(error: impl Display) -> Failure {
    Failure::Error(error.to_string())
}

/// Rejects a null output pointer. Early returns outside [`guard`] use this too,
/// so callers never read a stale message.
pub fn null_output() -> CurvyStatus {
    set_last_error("null output pointer");
    CurvyStatus::InvalidArgument
}

/// The status of an object `*_free` call.
pub fn free_status(removed: bool) -> CurvyStatus {
    if removed {
        CurvyStatus::Ok
    } else {
        set_last_error("unknown, freed, or wrong-type handle");
        CurvyStatus::InvalidHandle
    }
}

// Input helpers

/// # Safety
/// `ptr` must be null or a valid NUL-terminated UTF-8 string.
pub unsafe fn str_in<'a>(ptr: *const c_char) -> Result<&'a str, CurvyStatus> {
    if ptr.is_null() {
        set_last_error("null string argument");
        return Err(CurvyStatus::InvalidArgument);
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|_| {
        set_last_error("string argument is not UTF-8");
        CurvyStatus::InvalidArgument
    })
}

/// # Safety
/// `ptr`/`len` must describe a readable region, or `ptr` may be null when `len` is 0.
pub unsafe fn bytes_in<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], CurvyStatus> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() || len > isize::MAX as usize || (ptr as usize).checked_add(len).is_none() {
        set_last_error("null or out-of-range byte buffer argument");
        return Err(CurvyStatus::InvalidArgument);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Parses the JSON string-array ABI.
///
/// # Safety
/// `ptr` must be null or a valid NUL-terminated UTF-8 string.
pub unsafe fn str_vec_in(ptr: *const c_char) -> Result<Zeroizing<Vec<String>>, CurvyStatus> {
    let json = unsafe { str_in(ptr) }?;
    serde_json::from_str(json).map(Zeroizing::new).map_err(|_| {
        set_last_error("expected a JSON array of strings");
        CurvyStatus::InvalidArgument
    })
}

// Output helpers

/// Hands a NUL-terminated buffer to the caller as a C string.
///
/// The length must equal the capacity: `CString` boxes the vector, and shrinking
/// spare capacity reallocates, leaving an unwiped copy in the freed block.
fn c_string_out(bytes: Vec<u8>, out: *mut *mut c_char) -> CurvyStatus {
    debug_assert_eq!(bytes.len(), bytes.capacity());
    match CString::from_vec_with_nul(bytes) {
        Ok(owned) => {
            unsafe { std::ptr::write_unaligned(out, owned.into_raw()) };
            CurvyStatus::Ok
        }
        Err(error) => {
            error.into_bytes().zeroize();
            set_last_error("result contained an interior NUL byte");
            CurvyStatus::Error
        }
    }
}

/// Copies `value` into an exact-size C string and wipes the original.
pub fn string_out(value: String, out: *mut *mut c_char) -> CurvyStatus {
    let value = Zeroizing::new(value);
    if out.is_null() {
        return null_output();
    }
    // `Vec::with_capacity` allocates exactly the requested capacity, so neither
    // these writes nor the `CString` conversion reallocate.
    let mut bytes = Vec::with_capacity(value.len() + 1);
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    c_string_out(bytes, out)
}

/// Counts serialized bytes without storing them.
struct ByteCount(usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Encodes a JSON string array. Outputs can carry private keys, so the JSON is
/// sized first and written once into the buffer handed to the caller: a growing
/// buffer would free partial copies without wiping them.
pub fn str_vec_out(values: Vec<String>, out: *mut *mut c_char) -> CurvyStatus {
    let values = Zeroizing::new(values);
    if out.is_null() {
        return null_output();
    }
    let mut size = ByteCount(0);
    if let Err(error) = serde_json::to_writer(&mut size, &*values) {
        set_last_error(format!("could not encode result array: {error}"));
        return CurvyStatus::Error;
    }
    let mut json = Zeroizing::new(Vec::with_capacity(size.0 + 1));
    if let Err(error) = serde_json::to_writer(&mut *json, &*values) {
        set_last_error(format!("could not encode result array: {error}"));
        return CurvyStatus::Error;
    }
    json.push(0);
    c_string_out(std::mem::take(&mut *json), out)
}

pub fn bytes_out(mut value: Vec<u8>, out: *mut CurvyBytes) -> CurvyStatus {
    if out.is_null() {
        value.zeroize();
        return null_output();
    }
    unsafe { std::ptr::write_unaligned(out, CurvyBytes::from_vec(value)) };
    CurvyStatus::Ok
}

// A process hook is necessary because Rust runs it before catch_unwind. Chain
// the host hook outside our guarded calls; inside them, retain only a location.
// Hosts replacing the panic hook later must preserve this redaction behavior.
fn install_panic_hook() {
    let host_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // An inaccessible depth means thread teardown; redact rather than risk
        // forwarding a payload from a guarded call.
        if GUARD_DEPTH
            .try_with(|depth| depth.get() != 0)
            .unwrap_or(true)
        {
            let message = info.location().map_or_else(
                || "panic in curvy native core".to_string(),
                |location| {
                    format!(
                        "panic in curvy native core at {}:{}",
                        location.file(),
                        location.line()
                    )
                },
            );
            set_last_error(message);
        } else {
            host_hook(info);
        }
    }));
}

fn enter_guard() -> impl Drop {
    static HOOK: Once = Once::new();
    // `set_hook` panics on a panicking thread, e.g. a host `Drop` calling a free
    // during unwinding. Install on a later call instead.
    if !std::thread::panicking() {
        HOOK.call_once(install_panic_hook);
    }
    let _ = GUARD_DEPTH.try_with(|depth| depth.set(depth.get() + 1));
    struct ActiveGuard;
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            let _ = GUARD_DEPTH.try_with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }
    ActiveGuard
}

/// Converts panics into [`CurvyStatus::Panic`] without retaining their payload.
/// Each guarded call invalidates the previous error, including successful calls.
pub fn guard(body: impl FnOnce() -> CurvyStatus) -> CurvyStatus {
    catch_unwind(AssertUnwindSafe(|| {
        let _active = enter_guard();
        replace_last_error(None);
        body()
    }))
    .unwrap_or(CurvyStatus::Panic)
}

/// `guard` for call bodies that report a [`Failure`].
pub fn guard_result<T>(
    body: impl FnOnce() -> Result<T, Failure>,
    finish: impl FnOnce(T) -> CurvyStatus,
) -> CurvyStatus {
    guard(|| body().map_or_else(Failure::report, finish))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_impossible_slice_lengths_before_dereferencing() {
        let byte = 0_u8;
        assert_eq!(
            unsafe { bytes_in(&byte, isize::MAX as usize + 1) },
            Err(CurvyStatus::InvalidArgument)
        );
        assert_eq!(
            unsafe { bytes_in(usize::MAX as *const u8, 2) },
            Err(CurvyStatus::InvalidArgument)
        );
        assert!(unsafe { bytes_in(std::ptr::null(), 0) }.unwrap().is_empty());
    }
    #[test]
    fn panic_payload_is_redacted_and_success_clears_the_error() {
        assert_eq!(guard(|| panic!("PRIVATE_SENTINEL")), CurvyStatus::Panic);
        let message = unsafe { CStr::from_ptr(curvy_last_error()) }
            .to_str()
            .unwrap();
        assert!(message.contains("panic in curvy native core at"));
        assert!(!message.contains("PRIVATE_SENTINEL"));
        assert_eq!(guard(|| CurvyStatus::Ok), CurvyStatus::Ok);
        assert!(curvy_last_error().is_null());
    }
    #[test]
    fn string_outputs_are_exact_size_allocations() {
        let take = |status: CurvyStatus, out: *mut c_char| {
            assert_eq!(status, CurvyStatus::Ok);
            let owned = unsafe { CString::from_raw(out) };
            let bytes = owned.into_bytes_with_nul();
            // Exact capacity means no reallocation happened on the way out.
            assert_eq!(bytes.len(), bytes.capacity());
            String::from_utf8(bytes[..bytes.len() - 1].to_vec()).unwrap()
        };
        let values = vec!["0x01".repeat(40), String::new(), "a\"b".into()];
        let mut out = std::ptr::null_mut();
        let json = take(str_vec_out(values.clone(), &mut out), out);
        assert_eq!(json, serde_json::to_string(&values).unwrap());
        let json = take(string_out("x".repeat(1000), &mut out), out);
        assert_eq!(json, "x".repeat(1000));
        assert_eq!(
            str_vec_out(values, std::ptr::null_mut()),
            CurvyStatus::InvalidArgument
        );
        assert_eq!(string_out("a\0b".into(), &mut out), CurvyStatus::Error);
    }

    #[test]
    fn byte_outputs_keep_contents_with_or_without_spare_capacity() {
        for capacity in [0, 3, 64] {
            let mut value = Vec::with_capacity(capacity);
            value.extend_from_slice(&[7, 8, 9]);
            let mut out = CurvyBytes::empty();
            assert_eq!(bytes_out(value, &mut out), CurvyStatus::Ok);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(out.ptr, out.len) },
                [7, 8, 9]
            );
            unsafe { curvy_bytes_free(out) };
        }
    }
}
