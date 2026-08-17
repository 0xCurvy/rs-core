//! Per-type handle registry for stateful FFI objects.
//!
//! Handles are monotonic and never reused, so stale handles cannot resolve to a
//! different object. Callers release objects with the matching `*_free` function.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

pub struct Registry<T> {
    // Lazily initialized for use in statics.
    entries: LazyLock<Mutex<HashMap<u64, T>>>,
    next: AtomicU64,
}

impl<T> Registry<T> {
    pub const fn new() -> Self {
        Self {
            entries: LazyLock::new(|| Mutex::new(HashMap::new())),
            // 0 is reserved as "no handle" so a zeroed struct is never valid.
            next: AtomicU64::new(1),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, T>> {
        // The FFI guard reports the panic. Recover so later calls still work.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn insert(&self, value: T) -> u64 {
        let handle = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .expect("Curvy FFI handle space exhausted");
        self.lock().insert(handle, value);
        handle
    }

    pub fn remove(&self, handle: u64) -> bool {
        self.lock().remove(&handle).is_some()
    }

    /// Shared access. Returns `None` for an unknown or freed handle.
    pub fn with<R>(&self, handle: u64, body: impl FnOnce(&T) -> R) -> Option<R> {
        self.lock().get(&handle).map(body)
    }

    /// Exclusive access. Returns `None` for an unknown or freed handle.
    pub fn with_mut<R>(&self, handle: u64, body: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.lock().get_mut(&handle).map(body)
    }
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self::new()
    }
}
