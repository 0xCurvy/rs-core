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
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

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
    static GUARD_DEPTH: Cell<usize> = const { Cell::new(0) };
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

/// Returns this thread's last error, or null. Copy it before the next fallible call.
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
    zeroize::Zeroize::zeroize(&mut unsafe { CString::from_raw(ptr) }.into_bytes_with_nul());
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
    zeroize::Zeroize::zeroize(&mut owned[..]);
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
    if ptr.is_null() || len > isize::MAX as usize || (ptr as usize).checked_add(len).is_none() {
        return Err(CurvyStatus::InvalidArgument);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Parses the JSON string-array ABI.
///
/// # Safety
/// `ptr` must be null or a valid NUL-terminated UTF-8 string.
pub unsafe fn str_vec_in(
    ptr: *const c_char,
) -> Result<zeroize::Zeroizing<Vec<String>>, CurvyStatus> {
    let json = unsafe { str_in(ptr) }?;
    serde_json::from_str(json)
        .map(zeroize::Zeroizing::new)
        .map_err(|_| {
            set_last_error("expected a JSON array of strings");
            CurvyStatus::InvalidArgument
        })
}

// Output helpers

pub fn string_out(mut value: String, out: *mut *mut c_char) -> CurvyStatus {
    if out.is_null() {
        zeroize::Zeroize::zeroize(&mut value);
        return CurvyStatus::InvalidArgument;
    }
    match CString::new(value) {
        Ok(owned) => {
            unsafe { std::ptr::write_unaligned(out, owned.into_raw()) };
            CurvyStatus::Ok
        }
        Err(error) => {
            zeroize::Zeroize::zeroize(&mut error.into_vec());
            set_last_error("result contained an interior NUL byte");
            CurvyStatus::Error
        }
    }
}

pub fn str_vec_out(values: Vec<String>, out: *mut *mut c_char) -> CurvyStatus {
    let values = zeroize::Zeroizing::new(values);
    match serde_json::to_string(&*values) {
        Ok(json) => string_out(json, out),
        Err(error) => {
            set_last_error(format!("could not encode result array: {error}"));
            CurvyStatus::Error
        }
    }
}

pub fn bytes_out(mut value: Vec<u8>, out: *mut CurvyBytes) -> CurvyStatus {
    if out.is_null() {
        zeroize::Zeroize::zeroize(&mut value);
        return CurvyStatus::InvalidArgument;
    }
    unsafe { std::ptr::write_unaligned(out, CurvyBytes::from_vec(value)) };
    CurvyStatus::Ok
}

// A process hook is necessary because Rust runs it before catch_unwind. Chain
// the host hook outside our guarded calls; inside them, retain only a location.
// Hosts replacing the panic hook later must preserve this redaction behavior.
fn enter_guard() -> impl Drop {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let host_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if GUARD_DEPTH.with(|depth| depth.get() != 0) {
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
    });
    GUARD_DEPTH.with(|depth| depth.set(depth.get() + 1));
    struct ActiveGuard;
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            GUARD_DEPTH.with(|depth| depth.set(depth.get() - 1));
        }
    }
    ActiveGuard
}

/// Converts panics into [`CurvyStatus::Panic`] without retaining their payload.
/// Each guarded call invalidates the previous error, including successful calls.
pub fn guard(body: impl FnOnce() -> CurvyStatus) -> CurvyStatus {
    let _active = enter_guard();
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(status) => status,
        Err(_) => CurvyStatus::Panic,
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
}
