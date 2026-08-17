//! C ABI marshalling and error handling.
//!
//! * Strings use NUL-terminated UTF-8. Free Rust outputs with [`curvy_string_free`].
//! * String arrays use one JSON array string.
//! * Byte buffers use `(ptr, len)`. Free Rust outputs with [`curvy_bytes_free`].
//! * Fallible calls return [`CurvyStatus`] and write through an out-pointer.
//!   Read the current thread's error with [`curvy_last_error`].
//!
//! Entry points catch panics so they never unwind into C.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CurvyStatus {
    Ok = 0,
    /// A Rust-side error; call `curvy_last_error` for the message.
    Error = 1,
    /// A null pointer or non-UTF-8 string arrived from the caller.
    InvalidArgument = 2,
    /// A handle was unknown or already freed.
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
    pub fn from_vec(vec: Vec<u8>) -> Self {
        let boxed = vec.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed).cast::<u8>();
        Self { ptr, len }
    }
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub fn set_last_error(message: impl Into<String>) {
    let message = message.into();
    // A NUL inside an error message would truncate it; replace rather than drop.
    let sanitised = message.replace('\0', "\\0");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(sanitised).ok();
    });
}

/// Returns this thread's last error, or null. Copy it before the next failing call.
///
/// # Safety
/// The returned pointer is owned by Rust and must not be freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn curvy_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(std::ptr::null(), |message| message.as_ptr())
    })
}

/// # Safety
/// `ptr` must have come from this library and not been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(unsafe { CString::from_raw(ptr) });
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
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(bytes.ptr, bytes.len)) });
}

// Input helpers

/// # Safety
/// `ptr` must be null or a valid NUL-terminated UTF-8 string.
pub unsafe fn str_in<'a>(ptr: *const c_char) -> Result<&'a str, CurvyStatus> {
    if ptr.is_null() {
        return Err(CurvyStatus::InvalidArgument);
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| CurvyStatus::InvalidArgument)
}

/// # Safety
/// `ptr`/`len` must describe a readable region, or `ptr` may be null when `len` is 0.
pub unsafe fn bytes_in<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], CurvyStatus> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(CurvyStatus::InvalidArgument);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Parses the JSON string-array ABI.
///
/// # Safety
/// `ptr` must be null or a valid NUL-terminated UTF-8 string.
pub unsafe fn str_vec_in(ptr: *const c_char) -> Result<Vec<String>, CurvyStatus> {
    let json = unsafe { str_in(ptr) }?;
    serde_json::from_str(json).map_err(|error| {
        set_last_error(format!("expected a JSON array of strings: {error}"));
        CurvyStatus::InvalidArgument
    })
}

// Output helpers

pub fn string_out(value: String, out: *mut *mut c_char) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    match CString::new(value) {
        Ok(owned) => {
            unsafe { *out = owned.into_raw() };
            CurvyStatus::Ok
        }
        Err(_) => {
            set_last_error("result contained an interior NUL byte");
            CurvyStatus::Error
        }
    }
}

pub fn str_vec_out(values: Vec<String>, out: *mut *mut c_char) -> CurvyStatus {
    match serde_json::to_string(&values) {
        Ok(json) => string_out(json, out),
        Err(error) => {
            set_last_error(format!("could not encode result array: {error}"));
            CurvyStatus::Error
        }
    }
}

pub fn bytes_out(value: Vec<u8>, out: *mut CurvyBytes) -> CurvyStatus {
    if out.is_null() {
        return CurvyStatus::InvalidArgument;
    }
    unsafe { *out = CurvyBytes::from_vec(value) };
    CurvyStatus::Ok
}

/// Converts panics into [`CurvyStatus::Panic`] and records the message.
pub fn guard(body: impl FnOnce() -> CurvyStatus) -> CurvyStatus {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(status) => status,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic in curvy native core".to_string());
            set_last_error(message);
            CurvyStatus::Panic
        }
    }
}

/// `guard` for calls whose Rust error type is `Display`.
pub fn guard_result<T>(
    body: impl FnOnce() -> Result<T, String>,
    finish: impl FnOnce(T) -> CurvyStatus,
) -> CurvyStatus {
    guard(|| match body() {
        Ok(value) => finish(value),
        Err(message) => {
            set_last_error(message);
            CurvyStatus::Error
        }
    })
}
