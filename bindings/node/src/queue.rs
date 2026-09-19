use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use rayon::ThreadPool;

pub(crate) type Completion = Box<dyn FnOnce() + Send>;

/// One running job per prover. Waiting jobs occupy memory, never libuv workers.
pub(crate) struct SerialQueue<T> {
    pool: Arc<ThreadPool>,
    capacity: usize,
    execute: fn(T) -> Completion,
    state: Mutex<State<T>>,
}

struct State<T> {
    active: bool,
    outstanding: usize,
    waiting: VecDeque<T>,
}

impl<T: Send + 'static> SerialQueue<T> {
    pub(crate) fn new(
        pool: Arc<ThreadPool>,
        capacity: usize,
        execute: fn(T) -> Completion,
    ) -> Arc<Self> {
        assert!(capacity > 0);
        Arc::new(Self {
            pool,
            capacity,
            execute,
            state: Mutex::new(State {
                active: false,
                outstanding: 0,
                waiting: VecDeque::new(),
            }),
        })
    }

    /// The bound includes the running job. Rejection returns ownership to the
    /// caller so it can settle its promise without dropping an accepted request.
    pub(crate) fn submit(self: &Arc<Self>, job: T) -> Result<(), T> {
        let mut state = self.state.lock().expect("proof queue lock poisoned");
        if state.outstanding >= self.capacity {
            return Err(job);
        }
        state.waiting.push_back(job);
        state.outstanding += 1;
        if !state.active {
            state.active = true;
            let queue = Arc::clone(self);
            self.pool.spawn(move || queue.drain());
        }
        Ok(())
    }

    fn drain(&self) {
        loop {
            let job = {
                let mut state = self.state.lock().expect("proof queue lock poisoned");
                match state.waiting.pop_front() {
                    Some(job) => job,
                    None => {
                        state.active = false;
                        return;
                    }
                }
            };
            // Each job must convert computation panics into its own rejection.
            let complete = (self.execute)(job);
            self.state
                .lock()
                .expect("proof queue lock poisoned")
                .outstanding -= 1;
            // A promise callback may submit another job immediately. Release
            // its capacity before exposing completion to JavaScript.
            complete();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn bounded_queue_preserves_order_and_releases_capacity() {
        type Job = Box<dyn FnOnce() + Send>;
        let pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(2)
                .build()
                .unwrap(),
        );
        let queue = SerialQueue::new(pool, 2, |job: Job| {
            job();
            Box::new(|| {})
        });
        let (started, start) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let (finished, results) = mpsc::channel();
        let first = finished.clone();
        assert!(
            queue
                .submit(Box::new(move || {
                    started.send(()).unwrap();
                    gate.recv().unwrap();
                    first.send(1).unwrap();
                }))
                .is_ok()
        );
        start.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            queue
                .submit(Box::new(move || {
                    finished.send(2).unwrap();
                }))
                .is_ok()
        );
        assert!(
            queue
                .submit(Box::new(|| panic!("rejected job ran")))
                .is_err()
        );
        assert!(results.try_recv().is_err());
        release.send(()).unwrap();
        assert_eq!(results.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
        assert_eq!(results.recv_timeout(Duration::from_secs(5)).unwrap(), 2);
        let (sent, received) = mpsc::channel();
        assert!(
            queue
                .submit(Box::new(move || {
                    sent.send(3).unwrap();
                }))
                .is_ok()
        );
        assert_eq!(received.recv_timeout(Duration::from_secs(5)).unwrap(), 3);
    }
}
