// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The garbage-collection jobs a Plane provides to the Host API (WP-7.11b,
//! `6-contracts/8-contract-host-api.md` lifecycle, configuration and operations).
//!
//! The Host owns the plan receipt, its consumption and the audit of `POST /host/v1/gc/{job}/plan`
//! and `…/run`; the Plane that declared a job only answers what its sweep would remove and what
//! it removed. A job is one of a closed set, provided by one Plane.
//!
//! | Job       | Plane         | Receipt operation | Sweeps                                             |
//! | --------- | ------------- | ----------------- | -------------------------------------------------- |
//! | `objects` | Control Plane | `gc.objects`      | the objects no ref, pin, hold or grace keeps       |

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use permguard_core::authz::Resource;

use crate::operations::plan;

/// The Control Plane's object sweep.
pub const OBJECTS: &str = "objects";

/// Every job the Host API plans and runs.
pub const JOBS: &[&str] = &[OBJECTS];

/// The most resources a report lists one by one: the rest are counted in
/// [`Report::omitted`], so an answer stays one journal entry a retry is answered from.
pub const MAX_ENTRIES: usize = 256;

/// The operation a receipt of `job` names, for a job the Host knows.
pub fn plan_operation(job: &str) -> Option<&'static str> {
    match job {
        OBJECTS => Some(plan::GC_OBJECTS),
        _ => None,
    }
}

/// Objects a sweep kept for one reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kept {
    /// `reachable`, `pinned`, `grace`, `held` or `bound`.
    pub reason: String,
    pub count: u64,
}

/// What a sweep would remove, or removed, in one resource, and what it kept.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The resource, as a grant names it.
    pub resource: String,
    /// What the sweep found removable.
    pub candidates: u64,
    pub candidate_bytes: u64,
    /// What it removed: zero for a plan.
    pub removed: u64,
    pub removed_bytes: u64,
    pub kept: Vec<Kept>,
}

/// What a job's plan or run answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub entries: Vec<Entry>,
    /// The resource a run stopped in at its bound: what a later run removes.
    #[serde(default)]
    pub resumes_at: Option<String>,
    /// The resources the job could not read, and why: nothing of them was removed.
    #[serde(default)]
    pub skipped: Vec<String>,
    /// Resources past [`MAX_ENTRIES`] the report does not list, their counts still in the
    /// Plane's own record.
    #[serde(default)]
    pub omitted: u64,
}

/// Why a job did not plan or run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcError {
    /// The scope names nothing the Plane holds: no zone or ledger of it.
    NotFound(String),
    /// The job could not read what it sweeps.
    Failed(String),
}

impl std::fmt::Display for GcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(why) | Self::Failed(why) => f.write_str(why),
        }
    }
}

/// A job a Plane provides. `scope` is the Plane, or a zone or ledger of it, as the plan named it.
pub trait GcJob: Send + Sync {
    /// What a run would remove now, and what it would keep and why. Changes nothing.
    fn plan(&self, scope: &Resource) -> Result<Report, GcError>;

    /// Sweeps `scope` now, under every recheck the background pass makes and within its bound,
    /// serialized with it; `plan_id` names the plan it runs in the Plane's own record. Called
    /// off the async workers, and outside any Host operation.
    fn run(&self, scope: &Resource, plan_id: &str) -> Result<Report, GcError>;
}

/// The jobs the Planes provide: filled at registration, read by the Host API.
#[derive(Default)]
pub struct Jobs(Mutex<BTreeMap<&'static str, Provider>>);

/// The Plane that provides a job, and its handler.
type Provider = (String, Arc<dyn GcJob>);

impl std::fmt::Debug for Jobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let jobs = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_tuple("Jobs")
            .field(&jobs.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Jobs {
    /// `plane` provides `job` with `handler`; a job is provided once.
    pub fn provide(
        &self,
        job: &'static str,
        plane: &str,
        handler: Arc<dyn GcJob>,
    ) -> Result<(), String> {
        let mut jobs = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((first, _)) = jobs.get(job) {
            return Err(format!(
                "the gc job `{job}` is provided by `{first}` already"
            ));
        }
        jobs.insert(job, (plane.to_owned(), handler));
        Ok(())
    }

    /// The Plane that provides `job`, and its handler.
    pub fn get(&self, job: &str) -> Option<(String, Arc<dyn GcJob>)> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(job)
            .map(|(plane, handler)| (plane.clone(), Arc::clone(handler)))
    }
}
