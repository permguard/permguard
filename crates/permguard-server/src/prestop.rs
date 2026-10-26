// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `drain`: what a container's `preStop` hook runs (TD-1).
//!
//! An orchestrator scaling a group down runs the hook, then sends SIGTERM, then, once the grace
//! period is spent, SIGKILL. The blueprint wants the hook to *request* the drain and the grace
//! period to cover the hook and the process's shutdown together, not each in turn: a hook that only
//! slept would leave the drain to start after it.
//!
//! So the hook sends the server the SIGTERM itself — its readiness goes false at once and its
//! drain starts inside `shutdown.drain_timeout` — and returns. It does not wait for the server to
//! exit: the hook runs inside the server's own container, which ends when the server does, and an
//! orchestrator reports a hook ended that way as failed. The grace period the chart gives is
//! `shutdown.timeout` plus the seconds the signal takes, so the one budget covers the drain from
//! the moment the hook asks for it. The orchestrator's own SIGTERM, when it comes, finds the drain
//! under way: the server keeps its handler for the whole run (tokio never restores the default
//! action once it has installed one), and a process 1 is not ended by a signal it does not handle
//! anyway, so a second request is the same one.
//!
//! `--wait` is for an operator outside a container: it waits for the server to exit, and fails when
//! the server is still running at the end of it.
//!
//! The images have no shell, which is why this is a command of the binary rather than a `kill` in
//! the manifest. It reads no configuration and starts no log pipeline, so nothing in the
//! container's environment can stop it; nothing it does reaches a wire or the volume: it is a
//! signal, and perhaps a wait.

use std::io::Write;
use std::time::Duration;

use anyhow::{Result, bail};

/// How often the wait looks whether the server is still there.
#[cfg(unix)]
const POLL: Duration = Duration::from_millis(100);

/// Asks the server `pid` to drain and, when `wait` is not zero, waits up to `wait` for it to exit.
///
/// A server already gone has nothing left to drain, which is success. A server still running when
/// the wait ends is reported, and the command fails: whether its evidence shipped is what its
/// volume says (`unshipped`), not what this command can know.
#[cfg(unix)]
pub async fn drain(pid: u32, wait: Duration, out: &mut dyn Write) -> Result<()> {
    use anyhow::Context as _;
    use rustix::io::Errno;
    use rustix::process::{Pid, Signal, kill_process, test_kill_process};

    let raw = i32::try_from(pid).context("the process id is too large")?;
    let Some(target) = Pid::from_raw(raw) else {
        bail!("the process id is a positive number");
    };
    match kill_process(target, Signal::TERM) {
        Ok(()) => {}
        Err(Errno::SRCH) => {
            writeln!(
                out,
                "no server is running as process {pid}: nothing to drain"
            )
            .context("writing the result")?;
            return Ok(());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("asking process {pid} to drain"));
        }
    }
    if wait.is_zero() {
        writeln!(out, "asked the server (process {pid}) to drain").context("writing the result")?;
        return Ok(());
    }
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match test_kill_process(target) {
            Err(Errno::SRCH) => {
                writeln!(out, "the server (process {pid}) drained and exited")
                    .context("writing the result")?;
                return Ok(());
            }
            Ok(()) => {}
            Err(error) => {
                return Err(error).with_context(|| format!("watching process {pid}"));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "the server (process {pid}) is still running {}s after it was asked to drain: the \
                 grace period ends it, and its volume records whatever it did not ship",
                wait.as_secs()
            );
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Signals are a Unix vocabulary: there is nothing to send elsewhere.
#[cfg(not(unix))]
pub async fn drain(_pid: u32, _wait: Duration, _out: &mut dyn Write) -> Result<()> {
    bail!("`drain` signals a process, which this platform does not offer")
}
