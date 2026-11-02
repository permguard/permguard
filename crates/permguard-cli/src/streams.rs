// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where a command's output goes: this process's standard streams, or the two buffers of a
//! captured run. Every write a command makes comes through here, so a program that embeds the CLI
//! reads exactly what the binary would have printed, and a command never decides it alone.
//!
//! The choice is held per thread for the length of one run: two commands captured on two threads
//! never write into each other's buffers. A narrator a run hands to the transports keeps its own
//! handle, since the transports may call it from another thread.

use std::cell::RefCell;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};

use crate::style::Depth;

#[derive(Default)]
struct Buffers {
    out: Vec<u8>,
    err: Vec<u8>,
}

/// The buffers of one captured run, and the colours its output may carry.
#[derive(Clone)]
pub(crate) struct Capture {
    buffers: Arc<Mutex<Buffers>>,
    depth: Depth,
}

impl Capture {
    pub(crate) fn new(color: bool) -> Self {
        Self {
            buffers: Arc::default(),
            depth: if color { Depth::True } else { Depth::None },
        }
    }

    pub(crate) fn depth(&self) -> Depth {
        self.depth
    }

    /// Writes to the diagnostics of this capture.
    pub(crate) fn err(
        &self,
        write: impl FnOnce(&mut dyn Write) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut buffers = self.buffers.lock().unwrap_or_else(PoisonError::into_inner);
        write(&mut buffers.err)
    }

    /// The output and the diagnostics written so far, emptied.
    pub(crate) fn take(&self) -> (Vec<u8>, Vec<u8>) {
        let mut buffers = self.buffers.lock().unwrap_or_else(PoisonError::into_inner);
        (
            std::mem::take(&mut buffers.out),
            std::mem::take(&mut buffers.err),
        )
    }
}

thread_local! {
    static CAPTURE: RefCell<Option<Capture>> = const { RefCell::new(None) };
}

/// The capture of the run on this thread, if it is captured.
pub(crate) fn current() -> Option<Capture> {
    CAPTURE.with(|held| held.borrow().clone())
}

/// Runs `run` with this thread's output going to `capture`, then puts back what was there.
pub(crate) fn with_capture<T>(capture: Capture, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<Capture>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            CAPTURE.with(|held| *held.borrow_mut() = previous);
        }
    }

    let previous = CAPTURE.with(|held| held.borrow_mut().replace(capture));
    let _restore = Restore(previous);

    run()
}

/// Writes to the output: the capture's, or standard output, flushed.
pub(crate) fn out(write: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> io::Result<()> {
    match current() {
        Some(capture) => {
            let mut buffers = capture
                .buffers
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            write(&mut buffers.out)
        }
        None => {
            let mut stdout = io::stdout().lock();
            write(&mut stdout)?;
            stdout.flush()
        }
    }
}

/// Writes to the diagnostics: the capture's, or standard error.
pub(crate) fn err(write: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> io::Result<()> {
    match current() {
        Some(capture) => capture.err(write),
        None => write(&mut io::stderr().lock()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capture_holds_what_its_thread_writes_and_nothing_after() {
        let capture = Capture::new(false);
        with_capture(capture.clone(), || {
            out(|w| w.write_all(b"answer")).ok();
            err(|w| w.write_all(b"warning")).ok();
        });
        assert!(current().is_none());

        let (stdout, stderr) = capture.take();
        assert_eq!(stdout, b"answer");
        assert_eq!(stderr, b"warning");
    }

    #[test]
    fn two_threads_capture_apart() {
        let first = Capture::new(false);
        let second = Capture::new(false);
        let (a, b) = (first.clone(), second.clone());
        let one = std::thread::spawn(move || with_capture(a, || out(|w| w.write_all(b"one")).ok()));
        let two = std::thread::spawn(move || with_capture(b, || out(|w| w.write_all(b"two")).ok()));
        one.join().ok();
        two.join().ok();

        assert_eq!(first.take().0, b"one");
        assert_eq!(second.take().0, b"two");
    }
}
