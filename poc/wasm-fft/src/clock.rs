//! Wall clock and diagnostics that work natively and in a bare WASM module.
//!
//! The WASM build imports `env.now_ms` (the host's `performance.now()`) and
//! `env.log` instead of using wasm-bindgen, so one `.wasm` file runs unchanged
//! under Node and in Chromium.

#[cfg(target_arch = "wasm32")]
mod imp {
    #[link(wasm_import_module = "env")]
    unsafe extern "C" {
        #[link_name = "now_ms"]
        fn host_now_ms() -> f64;
        #[link_name = "log"]
        fn host_log(ptr: *const u8, len: usize);
    }

    pub fn now_ms() -> f64 {
        unsafe { host_now_ms() }
    }

    pub fn log(message: &str) {
        unsafe { host_log(message.as_ptr(), message.len()) }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();

    pub fn now_ms() -> f64 {
        START.get_or_init(Instant::now).elapsed().as_secs_f64() * 1e3
    }

    pub fn log(message: &str) {
        eprintln!("{message}");
    }
}

pub use imp::{log, now_ms};
