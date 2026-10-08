// SPDX-License-Identifier: GPL-3.0-or-later

//! One bounded worker pool per process, and the bounded buffer pool that
//! object I/O borrows from.
//!
//! The pool runs a fixed number of threads fed from a bounded queue, so
//! submitting blocks once the queue is full (backpressure). Coordinators —
//! the code that reads a source, writes an output in order, or collects
//! results — always run on the caller's thread, never on a worker, so no
//! worker ever waits for another and nested waiting cannot deadlock.
//! Dropping the pool closes the queue and joins every thread; jobs already
//! queued still run (each is bounded file I/O and crypto), and their
//! results are dropped if nobody waits for them. A panicking job is turned
//! into an error for whoever waits on it and does not take the worker down.

use crate::secret::SecretVec;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// The largest worker count accepted from the user.
pub const MAX_WORKERS: usize = 256;
/// The default cap: past this, the work is bound by storage, not CPU.
pub const DEFAULT_MAX_WORKERS: usize = 8;
/// Object-sized buffers in flight at once for one file.
pub const OBJECT_BUFFERS: usize = 8;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct Pool {
    tx: Option<SyncSender<Job>>,
    threads: Vec<JoinHandle<()>>,
}

impl Pool {
    pub fn new(workers: usize) -> Pool {
        assert!((1..=MAX_WORKERS).contains(&workers), "worker count out of range");
        let (tx, rx) = sync_channel::<Job>(workers * 2);
        let rx = Arc::new(Mutex::new(rx));
        let threads = (0..workers)
            .map(|i| {
                let rx = Arc::clone(&rx);
                std::thread::Builder::new()
                    .name(format!("vault-worker-{i}"))
                    .spawn(move || {
                        loop {
                            // Hold the lock only to take a job, not to run it.
                            let job = match rx.lock() {
                                Ok(r) => r.recv(),
                                Err(p) => p.into_inner().recv(),
                            };
                            match job {
                                Ok(job) => job(),
                                Err(_) => return,
                            }
                        }
                    })
                    .expect("spawn worker thread")
            })
            .collect();
        Pool { tx: Some(tx), threads }
    }

    /// The default worker count: available parallelism, at most 8.
    pub fn default_workers() -> usize {
        std::thread::available_parallelism().map_or(1, |n| n.get()).min(DEFAULT_MAX_WORKERS)
    }

    pub fn workers(&self) -> usize {
        self.threads.len()
    }

    /// Queues `f`, blocking while the queue is full.
    pub fn submit<T: Send + 'static>(&self, f: impl FnOnce() -> T + Send + 'static) -> Ticket<T> {
        let (rtx, rrx) = sync_channel(1);
        let job: Job = Box::new(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| "internal error: a worker panicked".to_string());
            let _ = rtx.send(r);
        });
        self.tx.as_ref().expect("pool open").send(job).expect("workers alive");
        Ticket(rrx)
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        drop(self.tx.take());
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// The pending result of a submitted job.
pub struct Ticket<T>(Receiver<Result<T, String>>);

impl<T> Ticket<T> {
    pub fn wait(self) -> Result<T, String> {
        self.0.recv().unwrap_or_else(|_| Err("internal error: a worker vanished".into()))
    }
}

/// A fixed set of reusable, equally sized secret buffers. Taking one blocks
/// until one is free; a buffer is cleared when it comes back, and every
/// buffer is cleared again when the pool is dropped.
#[derive(Clone)]
pub struct Buffers {
    tx: SyncSender<SecretVec>,
    rx: Arc<Mutex<Receiver<SecretVec>>>,
}

impl Buffers {
    pub fn new(count: usize, capacity: usize) -> Buffers {
        let (tx, rx) = sync_channel(count);
        for _ in 0..count {
            tx.send(SecretVec::with_capacity(capacity)).expect("room for every buffer");
        }
        Buffers {
            tx,
            rx: Arc::new(Mutex::new(rx)),
        }
    }

    pub fn take(&self) -> Lease {
        let b = match self.rx.lock() {
            Ok(r) => r.recv(),
            Err(p) => p.into_inner().recv(),
        }
        .expect("buffer pool alive");
        Lease {
            buf: Some(b),
            home: self.tx.clone(),
        }
    }
}

/// A borrowed buffer, returned (cleared) on drop — including when a job
/// fails or panics.
pub struct Lease {
    buf: Option<SecretVec>,
    home: SyncSender<SecretVec>,
}

impl Lease {
    pub fn buf(&mut self) -> &mut SecretVec {
        self.buf.as_mut().expect("leased")
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(mut b) = self.buf.take() {
            b.clear();
            let _ = self.home.send(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn results_in_submission_order_and_bounded_concurrency() {
        let pool = Pool::new(4);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let tickets: Vec<_> = (0..64)
            .map(|i| {
                let (running, peak) = (Arc::clone(&running), Arc::clone(&peak));
                pool.submit(move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis((64 - i) % 5));
                    running.fetch_sub(1, Ordering::SeqCst);
                    i
                })
            })
            .collect();
        let got: Vec<_> = tickets.into_iter().map(|t| t.wait().unwrap()).collect();
        assert_eq!(got, (0..64).collect::<Vec<_>>());
        assert!(peak.load(Ordering::SeqCst) <= 4);
    }

    #[test]
    fn panics_become_errors() {
        let pool = Pool::new(2);
        let t = pool.submit(|| -> u8 { panic!("boom") });
        assert!(t.wait().is_err());
        assert_eq!(pool.submit(|| 5).wait().unwrap(), 5, "worker survived");
    }

    #[test]
    fn dropping_tickets_and_pool_cleans_up() {
        for _ in 0..20 {
            let pool = Pool::new(3);
            for _ in 0..10 {
                drop(pool.submit(|| std::thread::sleep(Duration::from_millis(1))));
            }
            drop(pool); // joins: no threads outlive it
        }
    }

    #[test]
    fn buffers_are_bounded_and_cleared() {
        let b = Buffers::new(2, 8);
        let mut l1 = b.take();
        l1.buf().extend_within_capacity(b"secret");
        let _l2 = b.take();
        let b2 = b.clone();
        let waiter = std::thread::spawn(move || {
            let mut l = b2.take();
            l.buf().len()
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(!waiter.is_finished(), "a third lease should wait");
        drop(l1);
        assert_eq!(waiter.join().unwrap(), 0, "returned buffers are cleared");
    }
}
