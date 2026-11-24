// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The jobs that run on one instance at a time (iteration 03, WP-28.2): ring maintenance, the
//! re-pin of memberships, dormancy, the status lists' retirement, the audit sweep, the garbage
//! collections, the inventory and the deep verification.
//!
//! | Backend         | Who runs a job                                                                         |
//! | --------------- | -------------------------------------------------------------------------------------- |
//! | a volume        | the one process that claimed it: the volume's claim is the fence                       |
//! | `postgresql-s3` | the instance that holds the job's lease, kept to its expiry: once a cadence, whichever |
//!
//! A job decides whether it is due from what is stored, never from the instance's own timer: the
//! timer only asks. What it writes on its thread is written under its lease or not at all
//! (decision E27).

use std::sync::Arc;
use std::time::Duration;

/// Where the single jobs of a process are held.
pub trait SingleJobs: Send + Sync {
    /// Runs `work` on this thread as the one holder of the job `name`, held for `every` from
    /// now, and answers whether it ran: it does not while another instance holds the job. A
    /// hold is kept to its end, so a job runs once every `every` whichever instance asks;
    /// `work` answers whether it did its work, and one that did not gives the job up, so another
    /// instance may take it at its next turn rather than wait for a holder that keeps failing.
    fn run(
        &self,
        name: &str,
        every: Duration,
        work: &mut dyn FnMut() -> bool,
    ) -> Result<bool, String>;

    /// Whether the jobs are held among several instances: what another instance changed is
    /// then read again before a job, or a state held in memory, acts on it.
    fn shared(&self) -> bool {
        false
    }
}

/// The single jobs of a process that claimed a volume: it is the only one, and runs them all.
#[derive(Debug, Clone, Copy, Default)]
pub struct OnVolume;

impl SingleJobs for OnVolume {
    fn run(
        &self,
        _name: &str,
        _every: Duration,
        work: &mut dyn FnMut() -> bool,
    ) -> Result<bool, String> {
        work();
        Ok(true)
    }
}

/// The single jobs a composition hands its Planes, as a context's extension.
#[derive(Clone)]
pub struct Jobs(pub Arc<dyn SingleJobs>);

impl Jobs {
    /// The jobs of a process on a volume.
    pub fn on_volume() -> Self {
        Self(Arc::new(OnVolume))
    }

    /// Runs `work` as [`SingleJobs::run`] does, logging a hold that could not be asked for: the
    /// job is then not run, and the next turn asks again.
    pub fn run(&self, name: &str, every: Duration, work: &mut dyn FnMut() -> bool) -> bool {
        match self.0.run(name, every, work) {
            Ok(ran) => ran,
            Err(error) => {
                tracing::warn!(
                    event.name = "host.job_unheld",
                    component = "host",
                    job = name,
                    error = %error,
                    "the job's lease could not be asked for: it runs at a later turn"
                );
                false
            }
        }
    }
}

impl Jobs {
    /// Whether the jobs are held among several instances ([`SingleJobs::shared`]).
    pub fn shared(&self) -> bool {
        self.0.shared()
    }
}

impl std::fmt::Debug for Jobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jobs").finish_non_exhaustive()
    }
}
