//! One OS thread for desktop calls.
//!
//! DXGI and UI Automation want a stable thread. Portal clients want a thread
//! that is not already inside the node's Tokio runtime. The worker owns the
//! platform state; callers only send closures.

use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, Sender};
use std::thread;

use crate::error::{msg, Result};

pub struct Worker<S: 'static> {
    tx: Sender<Box<dyn FnOnce(&mut S) + Send>>,
    _tag: PhantomData<fn(&mut S)>,
}

impl<S: 'static> Clone for Worker<S> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            _tag: PhantomData,
        }
    }
}

impl<S: 'static> Worker<S> {
    pub fn spawn(init: impl FnOnce() -> S + Send + 'static) -> Self {
        let (tx, rx) = mpsc::channel::<Box<dyn FnOnce(&mut S) + Send>>();
        thread::Builder::new()
            .name("agentlink-desktop".into())
            .spawn(move || {
                let mut state = init();
                while let Ok(job) = rx.recv() {
                    job(&mut state);
                }
            })
            .expect("spawn agentlink desktop thread");
        Self {
            tx,
            _tag: PhantomData,
        }
    }

    pub fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut S) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(Box::new(move |state| {
                let result = catch_unwind(AssertUnwindSafe(|| f(state)));
                let mapped = match result {
                    Ok(value) => value,
                    Err(_) => Err(msg("desktop backend panicked")),
                };
                let _ = reply_tx.send(mapped);
            }))
            .map_err(|_| msg("desktop thread stopped"))?;
        reply_rx.recv().map_err(|_| msg("desktop thread stopped"))?
    }
}
