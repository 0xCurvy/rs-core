//! Development-only phase timing (`bench`): named spans around the resident
//! load and proof phases, read back in order with [`take`] (natively, and as
//! `takePhaseTimings` in a `--bench` WASM build). Without `bench`, the
//! crate-internal `phase!` macro is just its body.
//!
//! Spans are recorded on the calling thread, around whole phases; work a
//! phase hands to the Rayon pool is inside its span. Nested spans are
//! recorded too, so a parent includes its children.

/// Times `$body` as phase `$name` under `bench`; otherwise evaluates it.
macro_rules! phase {
    ($name:literal, $body:expr) => {{
        #[cfg(feature = "bench")]
        let _span = $crate::phase_timing::Span::new($name);
        $body
    }};
}
pub(crate) use phase;

#[cfg(feature = "bench")]
pub(crate) use imp::Span;
#[cfg(feature = "bench")]
pub use imp::take;

#[cfg(feature = "bench")]
mod imp {
    use std::sync::{Mutex, PoisonError};

    static PHASES: Mutex<Vec<(&'static str, f64)>> = Mutex::new(Vec::new());

    pub(crate) struct Span {
        name: &'static str,
        start: f64,
    }

    impl Span {
        pub(crate) fn new(name: &'static str) -> Self {
            Span { name, start: now() }
        }
    }

    impl Drop for Span {
        fn drop(&mut self) {
            let ms = now() - self.start;
            PHASES
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((self.name, ms));
        }
    }

    /// The spans recorded since the last call, in completion order, as
    /// (name, milliseconds).
    pub fn take() -> Vec<(&'static str, f64)> {
        core::mem::take(&mut *PHASES.lock().unwrap_or_else(PoisonError::into_inner))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn now() -> f64 {
        use std::{sync::OnceLock, time::Instant};
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_secs_f64() * 1_000.0
    }

    // `performance` is a global in windows, workers and Node.
    #[cfg(all(target_arch = "wasm32", feature = "wasm"))]
    fn now() -> f64 {
        #[wasm_bindgen::prelude::wasm_bindgen]
        extern "C" {
            #[wasm_bindgen(js_namespace = performance, js_name = now)]
            fn performance_now() -> f64;
        }
        performance_now()
    }

    #[cfg(all(target_arch = "wasm32", not(feature = "wasm")))]
    fn now() -> f64 {
        0.0
    }
}
