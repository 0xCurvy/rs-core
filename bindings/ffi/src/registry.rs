//! Per-type handle registry for stateful FFI objects.
//!
//! Handles are monotonic and never reused, so stale handles cannot resolve to a
//! different object. Callers release objects with the matching `*_free` function.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

pub struct Registry<T> {
    // Lazily initialized for use in statics.
    // The map lock protects only handle lookup/removal. Each value has its own
    // lock so a long proof or tree update does not serialize unrelated handles.
    entries: LazyLock<Mutex<HashMap<u64, Arc<Mutex<T>>>>>,
}

impl<T> Registry<T> {
    pub const fn new() -> Self {
        Self {
            entries: LazyLock::new(|| Mutex::new(HashMap::new())),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Arc<Mutex<T>>>> {
        // The FFI guard reports the panic. Recover so later calls still work.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn insert(&self, value: T) -> u64 {
        let handle = NEXT_HANDLE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .expect("Curvy FFI handle space exhausted");
        self.lock().insert(handle, Arc::new(Mutex::new(value)));
        handle
    }

    pub fn remove(&self, handle: u64) -> bool {
        self.remove_with(handle, |_| {})
    }

    /// Removes the handle and clears its value while holding the object lock.
    /// Queued operations may retain an Arc but can only observe the cleared value.
    pub fn remove_with(&self, handle: u64, clear: impl FnOnce(&mut T)) -> bool {
        let Some(value) = self.lock().remove(&handle) else {
            return false;
        };
        // Wait for the active operation without holding the registry map lock.
        let mut guard = value.lock().unwrap_or_else(PoisonError::into_inner);
        clear(&mut guard);
        true
    }

    /// Shared access. Returns `None` for an unknown or freed handle.
    pub fn with<R>(&self, handle: u64, body: impl FnOnce(&T) -> R) -> Option<R> {
        let value = Arc::clone(self.lock().get(&handle)?);
        let value = value.lock().unwrap_or_else(PoisonError::into_inner);
        Some(body(&value))
    }

    /// Exclusive access. Returns `None` for an unknown or freed handle.
    pub fn with_mut<R>(&self, handle: u64, body: impl FnOnce(&mut T) -> R) -> Option<R> {
        let value = Arc::clone(self.lock().get(&handle)?);
        let mut value = value.lock().unwrap_or_else(PoisonError::into_inner);
        Some(body(&mut value))
    }
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;

    use super::Registry;

    #[test]
    fn removal_clears_secrets_even_when_an_operation_retains_a_reference() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Key(Arc<AtomicBool>);
        impl Drop for Key {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let cleared = Arc::new(AtomicBool::new(false));
        let registry = Registry::new();
        let handle = registry.insert(Some(Key(Arc::clone(&cleared))));
        let pending = Arc::clone(registry.lock().get(&handle).unwrap());
        assert!(registry.remove_with(handle, |key| drop(key.take())));
        assert!(cleared.load(Ordering::SeqCst));
        assert!(pending.lock().unwrap().is_none());
        assert!(registry.with(handle, |_| ()).is_none());
    }

    #[test]
    fn unrelated_handles_do_not_hold_the_registry_map_lock() {
        let registry = Arc::new(Registry::new());
        let first = registry.insert(1_u8);
        let second = registry.insert(2_u8);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (first_release_tx, first_release_rx) = mpsc::channel();
        let (second_release_tx, second_release_rx) = mpsc::channel();

        let first_registry = Arc::clone(&registry);
        let first_entered = entered_tx.clone();
        let first_worker = thread::spawn(move || {
            first_registry.with(first, |_| {
                first_entered.send(first).unwrap();
                first_release_rx.recv().unwrap();
            })
        });
        let second_registry = Arc::clone(&registry);
        let second_worker = thread::spawn(move || {
            second_registry.with(second, |_| {
                entered_tx.send(second).unwrap();
                second_release_rx.recv().unwrap();
            })
        });

        let entered_first = entered_rx.recv_timeout(Duration::from_secs(2));
        let entered_second = entered_rx.recv_timeout(Duration::from_secs(2));
        first_release_tx.send(()).unwrap();
        second_release_tx.send(()).unwrap();
        first_worker.join().unwrap();
        second_worker.join().unwrap();

        let mut entered = [entered_first.unwrap(), entered_second.unwrap()];
        entered.sort_unstable();
        assert_eq!(entered, [first, second]);
    }
}
