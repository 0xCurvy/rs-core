use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use rayon::ThreadPool;

pub(crate) type Completion = Box<dyn FnOnce() + Send>;

/// Why `submit` returned a job without accepting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    Full,
    Closed,
}

/// One running job per prover. Waiting jobs occupy memory, never libuv workers.
pub(crate) struct SerialQueue<T> {
    capacity: usize,
    execute: fn(T) -> Completion,
    state: Mutex<State<T>>,
}

struct State<T> {
    /// Taken (and so terminated) once the queue is closed and idle.
    pool: Option<ThreadPool>,
    active: bool,
    closed: bool,
    outstanding: usize,
    waiting: VecDeque<T>,
    on_release: Vec<Completion>,
}

impl<T: Send + 'static> SerialQueue<T> {
    pub(crate) fn new(
        pool: ThreadPool,
        capacity: usize,
        execute: fn(T) -> Completion,
    ) -> Arc<Self> {
        assert!(capacity > 0);
        Arc::new(Self {
            capacity,
            execute,
            state: Mutex::new(State {
                pool: Some(pool),
                active: false,
                closed: false,
                outstanding: 0,
                waiting: VecDeque::new(),
                on_release: Vec::new(),
            }),
        })
    }

    /// The bound includes the running job. Rejection returns ownership to the
    /// caller so it can settle its promise without dropping an accepted request.
    pub(crate) fn submit(self: &Arc<Self>, job: T) -> Result<(), (T, Rejection)> {
        let mut state = self.state.lock().expect("proof queue lock poisoned");
        if state.closed {
            return Err((job, Rejection::Closed));
        }
        if state.outstanding >= self.capacity {
            return Err((job, Rejection::Full));
        }
        state.waiting.push_back(job);
        state.outstanding += 1;
        if !state.active {
            state.active = true;
            let queue = Arc::clone(self);
            state
                .pool
                .as_ref()
                .expect("an open queue owns its pool")
                .spawn(move || queue.drain());
        }
        Ok(())
    }

    /// Stop accepting jobs. Every job accepted earlier still runs; the pool is
    /// released after the last one completes, and then `on_release` runs. When
    /// the queue is already idle, both happen before this returns. Closing an
    /// already-closed queue only registers another `on_release`.
    pub(crate) fn close(&self, on_release: Completion) {
        let mut state = self.state.lock().expect("proof queue lock poisoned");
        state.closed = true;
        if state.active {
            state.on_release.push(on_release);
            return;
        }
        let pool = state.pool.take();
        drop(state);
        // Non-blocking: Rayon only signals its idle workers to exit.
        drop(pool);
        on_release();
    }

    fn drain(&self) {
        loop {
            let job = {
                let mut state = self.state.lock().expect("proof queue lock poisoned");
                match state.waiting.pop_front() {
                    Some(job) => job,
                    None => {
                        state.active = false;
                        if !state.closed {
                            return;
                        }
                        // Dropping the pool from one of its own workers is
                        // safe: this worker exits once `drain` returns.
                        let pool = state.pool.take();
                        let on_release = std::mem::take(&mut state.on_release);
                        drop(state);
                        drop(pool);
                        for release in on_release {
                            release();
                        }
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

    type Job = Box<dyn FnOnce() + Send>;

    fn queue(capacity: usize) -> Arc<SerialQueue<Job>> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        SerialQueue::new(pool, capacity, |job: Job| {
            job();
            Box::new(|| {})
        })
    }

    #[test]
    fn bounded_queue_preserves_order_and_releases_capacity() {
        let queue = queue(2);
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
        assert!(matches!(
            queue.submit(Box::new(|| panic!("rejected job ran"))),
            Err((_, Rejection::Full))
        ));
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

    #[test]
    fn close_drains_accepted_jobs_then_releases_once_idle() {
        let queue = queue(4);
        let (started, start) = mpsc::channel();
        let (release, gate) = mpsc::channel::<()>();
        let (events, log) = mpsc::channel();
        let running = events.clone();
        assert!(
            queue
                .submit(Box::new(move || {
                    started.send(()).unwrap();
                    gate.recv().unwrap();
                    running.send("running").unwrap();
                }))
                .is_ok()
        );
        start.recv_timeout(Duration::from_secs(5)).unwrap();
        let waiting = events.clone();
        assert!(
            queue
                .submit(Box::new(move || waiting.send("waiting").unwrap()))
                .is_ok()
        );
        let first_close = events.clone();
        queue.close(Box::new(move || first_close.send("released").unwrap()));
        let second_close = events.clone();
        queue.close(Box::new(move || {
            second_close.send("released again").unwrap()
        }));
        assert!(matches!(
            queue.submit(Box::new(|| panic!("job accepted after close"))),
            Err((_, Rejection::Closed))
        ));
        assert!(log.try_recv().is_err());

        release.send(()).unwrap();
        let mut seen = (0..4)
            .map(|_| log.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(&seen[..2], ["running", "waiting"]);
        seen[2..].sort_unstable();
        assert_eq!(&seen[2..], ["released", "released again"]);
        assert!(queue.state.lock().unwrap().pool.is_none());

        // Closing an idle, released queue settles immediately.
        let idle = events.clone();
        queue.close(Box::new(move || idle.send("idle").unwrap()));
        assert_eq!(log.try_recv().unwrap(), "idle");
    }
}
