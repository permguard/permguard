// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The supervised worker: a runtime evaluated in a local process the OS bounds and the supervisor
//! can kill.
//!
//! # Why a process
//!
//! A cooperative deadline limits only an engine that reaches its check, and nothing in-process
//! bounds an engine's memory. Where a runtime's worst case cannot be bounded in-process, the
//! languages model requires it to run in a supervised worker from the `production` profile upward,
//! or not at all. A process has limits a thread does not: `setrlimit` on its address space and its
//! CPU, applied before it runs a line of engine code, and a kill that frees everything it held.
//!
//! # The shape, as the owner decided it
//!
//! - **The same binary.** The supervisor starts the executable it is running from with
//!   [`WORKER_ARGUMENT`] as its first argument; each binary that evaluates calls [`serve_if_worker`]
//!   first thing in `main`, so the argument is a hidden internal command no public or Host API
//!   exposes.
//! - **A small pool of long-lived workers per runtime**, so a decision does not pay a process
//!   start, and bounded: a caller that finds every worker busy waits for one until its deadline.
//! - **Length-prefixed CBOR frames** on a private descriptor the worker took over from its
//!   standard output: a big-endian `u32` length, then one canonical CBOR map. JSON payloads — a
//!   query, a verdict — travel as JSON text inside the map, because the canonical CBOR profile
//!   carries no floats. An engine that writes to standard output writes to nothing.
//! - **Compile once per partition.** A worker receives a partition's bytes once, under their
//!   SHA-256 checksum, compiles them and keeps the program; later evaluations name the checksum. A
//!   frame whose bytes do not match its checksum is refused, and so is a worker whose runtime
//!   descriptor differs from the supervisor's — a binary replaced on disk would otherwise answer
//!   with another engine.
//! - **Kill at the deadline.** The supervisor waits for a verdict until the decision's deadline,
//!   then kills the worker and starts another: `E` `evaluation_deadline_exceeded`. A worker that
//!   panics, crashes or answers out of protocol is replaced: `E` `evaluation_panicked`. A compile
//!   still running at a request's deadline is left to finish in the background, so a partition
//!   slower to compile than one request's budget is not killed mid-compile on every request.
//! - **OS limits before any code**: `RLIMIT_AS` where the platform enforces it, `RLIMIT_CPU`, and
//!   `RLIMIT_CORE` 0 so a dying worker never writes the policies and requests it held to disk. A
//!   worker is retired before its cumulative CPU budget could kill it mid-evaluation.
//! - **Unix only.** Elsewhere a supervisor cannot be built, and a runtime that requires one is
//!   refused.
//!
//! No built-in runtime adopts it in TL-2; TL-4 (Rego) and TL-5 (Dogwood) do, and the Host's
//! assurance profile decides when one must.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use permguard_objects::cbor::{self, Value as Cbor};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::artifact::{ArtifactBlob, Artifacts, artifact_type};
use crate::evaluate::{
    Action, Entity, Evaluating, EvaluationError, Evaluator, Query, StoredPolicy, Verdict,
};
use crate::input::PartitionData;

/// The hidden first argument that turns a binary into a worker.
pub const WORKER_ARGUMENT: &str = "__permguard-evaluation-worker";

/// The largest frame either side reads: a bound on what a corrupted or hostile length can make
/// the reader allocate.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// How many compiled partitions one worker keeps before it starts again from empty. The supervisor
/// applies the same rule to its record of what a worker holds, so the two never disagree.
const WORKER_PROGRAMS: usize = 64;

/// Where a worker finds the runtimes it compiles: the registry in a real binary, test runtimes in
/// a test.
pub trait Catalogue: Sync {
    /// The evaluating half of the runtime `name`.
    fn evaluating(&self, name: &str) -> Option<&dyn Evaluating>;
    /// The descriptor digest of the runtime `name`.
    fn descriptor_digest(&self, name: &str) -> Option<String>;
}

/// The runtimes this build carries.
pub struct Registry;

impl Catalogue for Registry {
    fn evaluating(&self, name: &str) -> Option<&dyn Evaluating> {
        crate::registry::evaluating(name)
    }

    fn descriptor_digest(&self, name: &str) -> Option<String> {
        crate::descriptor::descriptor_digest(name).map(ToOwned::to_owned)
    }
}

/// Whether this process was started as a worker: its first argument, compared as an OS string so
/// that a path or argument that is not UTF-8 is simply not the worker argument.
pub fn started_as_worker() -> bool {
    std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(WORKER_ARGUMENT))
}

/// Serves as a worker, and exits, when this process was started as one.
///
/// Called first by every binary that evaluates, before it parses a command line, reads a
/// configuration or starts a runtime: a worker does nothing but answer frames.
pub fn serve_if_worker() {
    if !started_as_worker() {
        return;
    }
    std::process::exit(serve_on_protocol(&Registry));
}

/// Serves `catalogue` as a worker on this process's protocol descriptors: frames in on standard
/// input, out on the private descriptor [`protocol_output`] takes over from standard output.
/// Returns the exit code.
pub fn serve_on_protocol(catalogue: &dyn Catalogue) -> i32 {
    match protocol_output() {
        Ok(mut output) => serve(catalogue, &mut std::io::stdin().lock(), &mut output),
        Err(_) => 4,
    }
}

/// The frames' output: the standard output this process was started with, moved to a private
/// descriptor, and standard output pointed at standard error — which the supervisor discards — so
/// that an engine writing to standard output cannot corrupt the protocol.
#[cfg(unix)]
fn protocol_output() -> std::io::Result<std::fs::File> {
    use std::os::fd::FromRawFd as _;

    // SAFETY: `fcntl` and `dup2` act on this process's own descriptors 1 and 2, which exist; the
    // descriptor `fcntl` returns is close-on-exec and owned by the `File` built from it alone.
    unsafe {
        let protocol = libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 3);
        if protocol < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::dup2(2, 1) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(std::fs::File::from_raw_fd(protocol))
    }
}

#[cfg(not(unix))]
fn protocol_output() -> std::io::Result<std::io::Stdout> {
    Ok(std::io::stdout())
}

/// The worker loop: answers frames until its input ends. Returns the process exit code.
///
/// A panic is not caught here on purpose: a worker that came apart is not one to keep using, and
/// the supervisor reads its exit as `E` `evaluation_panicked` and starts another.
pub fn serve(catalogue: &dyn Catalogue, input: &mut dyn Read, output: &mut dyn Write) -> i32 {
    let mut programs: HashMap<String, Box<dyn Evaluator>> = HashMap::new();
    loop {
        let frame = match read_frame(input) {
            Ok(Some(frame)) => frame,
            Ok(None) => return 0,
            Err(_) => return 2,
        };
        let reply = answer(catalogue, &mut programs, &frame);
        if write_frame(output, &reply).is_err() {
            return 3;
        }
    }
}

fn answer(
    catalogue: &dyn Catalogue,
    programs: &mut HashMap<String, Box<dyn Evaluator>>,
    frame: &Cbor,
) -> Cbor {
    match text(frame, "op").as_deref() {
        Some("hello") => {
            let language = text(frame, "language").unwrap_or_default();
            match catalogue.descriptor_digest(&language) {
                Some(digest) => map(&[
                    ("op", Cbor::Text("hello".into())),
                    ("descriptor", Cbor::Text(digest)),
                ]),
                None => refused(
                    "runtime_unknown",
                    &format!("this worker carries no `{language}`"),
                ),
            }
        }
        Some("compile") => {
            let (Some(language), Some(checksum), Some(material)) = (
                text(frame, "language"),
                text(frame, "checksum"),
                bytes(frame, "partition"),
            ) else {
                return refused(
                    "frame_malformed",
                    "a compile frame names a language, a checksum and a partition",
                );
            };
            if hex_sha256(&material) != checksum {
                return refused(
                    "checksum_mismatch",
                    "the partition's bytes do not match the checksum they were sent under",
                );
            }
            let Some(engine) = catalogue.evaluating(&language) else {
                return refused(
                    "runtime_unknown",
                    &format!("this worker carries no `{language}`"),
                );
            };
            let Ok((policies, artifacts)) = decode_material(&material) else {
                return refused("frame_malformed", "the partition does not decode");
            };
            match crate::headroom::with(|| engine.compile(&policies, &artifacts)) {
                Ok(program) => {
                    if programs.len() >= WORKER_PROGRAMS {
                        programs.clear();
                    }
                    programs.insert(checksum, program);
                    map(&[("op", Cbor::Text("compiled".into()))])
                }
                Err(message) => refused("compile_refused", &message),
            }
        }
        Some("check_input") => {
            let (Some(checksum), Some(input)) = (text(frame, "checksum"), bytes(frame, "input"))
            else {
                return refused(
                    "frame_malformed",
                    "a check frame names a checksum and an input",
                );
            };
            let Some(program) = programs.get(&checksum) else {
                return map(&[("op", Cbor::Text("missing".into()))]);
            };
            let Ok(input) = decode_input(&input) else {
                return refused("frame_malformed", "the input does not decode");
            };
            match crate::headroom::with(|| program.check_input(&input)) {
                Ok(()) => map(&[("op", Cbor::Text("checked".into()))]),
                Err(message) => refused("input_refused", &message),
            }
        }
        Some("evaluate") => {
            let (Some(checksum), Some(query)) = (text(frame, "checksum"), bytes(frame, "query"))
            else {
                return refused(
                    "frame_malformed",
                    "an evaluate frame names a checksum and a query",
                );
            };
            let Some(program) = programs.get(&checksum) else {
                return map(&[("op", Cbor::Text("missing".into()))]);
            };
            let remaining = int(frame, "remaining_ms");
            let Ok(query) = decode_query(&query, remaining) else {
                return refused("frame_malformed", "the query does not decode");
            };
            let verdict = crate::headroom::with(|| program.evaluate(&query));
            map(&[
                ("op", Cbor::Text("verdict".into())),
                ("verdict", Cbor::Bytes(encode_verdict(&verdict))),
            ])
        }
        _ => refused(
            "frame_malformed",
            "a frame names no operation this worker knows",
        ),
    }
}

/// The OS limits a worker runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `RLIMIT_AS`, in bytes, where the platform enforces it.
    pub address_space: Option<u64>,
    /// `RLIMIT_CPU`, in seconds of CPU over the worker's whole life. A worker is retired once its
    /// busy time reaches half of it, so the limit only ever stops runaway work.
    pub cpu_seconds: Option<u64>,
    /// How long a compile, or an evaluation with no deadline of its own, may take before the
    /// worker is killed.
    pub wall_clock: Duration,
}

impl Default for Limits {
    /// 2 GiB of address space, 600 s of CPU, 30 s of wall clock: limits a supervisor always
    /// applies, which a deployment narrows for the runtime it isolates.
    fn default() -> Self {
        Self {
            address_space: Some(2 * 1024 * 1024 * 1024),
            cpu_seconds: Some(600),
            wall_clock: Duration::from_secs(30),
        }
    }
}

/// Why a supervisor could not be built or a partition not compiled in one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

#[cfg(unix)]
pub use supervised::Supervisor;

#[cfg(unix)]
mod supervised {
    use std::collections::HashSet;
    use std::io::{BufReader, BufWriter};
    use std::path::PathBuf;
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{Receiver, RecvTimeoutError};
    use std::sync::{Condvar, Mutex};

    use super::*;

    /// How many worker processes are alive, and the signal that one went away.
    #[derive(Default)]
    struct Live {
        count: Mutex<usize>,
        freed: Condvar,
    }

    /// One runtime's pool of workers.
    pub struct Supervisor {
        executable: PathBuf,
        arguments: Vec<String>,
        language: String,
        descriptor: String,
        limits: Limits,
        idle: Mutex<Vec<Worker>>,
        live: Arc<Live>,
        size: usize,
    }

    struct Worker {
        child: Child,
        input: BufWriter<ChildStdin>,
        replies: Receiver<Result<Cbor, String>>,
        /// What this worker holds, by checksum: kept in step with the worker's own eviction.
        compiled: HashSet<String>,
        /// The time spent waiting on this worker, an upper bound on the CPU it has used.
        busy: Duration,
        live: Arc<Live>,
    }

    impl Worker {
        fn holds(&mut self, checksum: &str) {
            if self.compiled.len() >= WORKER_PROGRAMS {
                self.compiled.clear();
            }
            self.compiled.insert(checksum.to_owned());
        }
    }

    impl Drop for Worker {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Ok(mut count) = self.live.count.lock() {
                *count = count.saturating_sub(1);
                self.live.freed.notify_one();
            }
        }
    }

    /// What a worker handed to the background still owes.
    enum Pending {
        Hello,
        Compile(String),
    }

    /// What an exchange with a worker came to.
    enum Exchange {
        Reply(Cbor),
        Late,
        Broken(String),
    }

    /// Why a worker could not be had or could not compile.
    struct WorkerError {
        kind: Kind,
        message: String,
    }

    enum Kind {
        Refused,
        Late,
        Broken,
    }

    impl WorkerError {
        fn refused(message: String) -> Self {
            Self {
                kind: Kind::Refused,
                message,
            }
        }
        fn late(message: &str) -> Self {
            Self {
                kind: Kind::Late,
                message: message.to_owned(),
            }
        }
        fn broken(message: String) -> Self {
            Self {
                kind: Kind::Broken,
                message,
            }
        }
        fn is_late(&self) -> bool {
            matches!(self.kind, Kind::Late)
        }

        fn into_verdict(self) -> Verdict {
            match self.kind {
                Kind::Refused => Verdict::engine_failed(self.message),
                Kind::Late => Verdict::deadline_exceeded(self.message),
                Kind::Broken => Verdict::panicked(self.message),
            }
        }
    }

    impl Supervisor {
        /// A pool of at most `size` workers for `language`, started from this process's own
        /// executable.
        pub fn new(language: &str, limits: Limits, size: usize) -> Result<Arc<Self>, Refused> {
            Self::with_executable(
                own_executable()?,
                Vec::new(),
                language,
                limits,
                size,
                &Registry,
            )
        }

        /// The same, started from `executable` with `arguments` after the worker argument — what a
        /// test whose own binary is the worker uses.
        pub fn with_executable(
            executable: PathBuf,
            arguments: Vec<String>,
            language: &str,
            limits: Limits,
            size: usize,
            catalogue: &dyn Catalogue,
        ) -> Result<Arc<Self>, Refused> {
            let descriptor = catalogue
                .descriptor_digest(language)
                .ok_or_else(|| Refused(format!("this build carries no `{language}`")))?;
            Ok(Arc::new(Self {
                executable,
                arguments,
                language: language.to_owned(),
                descriptor,
                limits,
                idle: Mutex::new(Vec::new()),
                live: Arc::default(),
                size: size.max(1),
            }))
        }

        /// Compiles a partition in a worker, and answers an evaluator that evaluates it there.
        ///
        /// The compile happens now, so a partition the runtime refuses is refused at load, as an
        /// in-process compile would be.
        pub fn compile(
            self: &Arc<Self>,
            policies: &[StoredPolicy],
            artifacts: &Artifacts,
        ) -> Result<Box<dyn Evaluator>, String> {
            let material = encode_material(policies, artifacts);
            // Under the frame bound with room for the frame around it: a partition the worker
            // would refuse to read is refused here, by name, rather than as a broken worker.
            if material.len() > MAX_FRAME - 1024 * 1024 {
                return Err(format!(
                    "the partition is {} bytes, more than a supervised worker accepts ({} bytes)",
                    material.len(),
                    MAX_FRAME - 1024 * 1024
                ));
            }
            let checksum = hex_sha256(&material);
            let deadline = Instant::now() + self.limits.wall_clock;
            let mut worker = self.worker(deadline).map_err(|error| error.message)?;
            self.compile_in(&mut worker, &checksum, &material, deadline, false)
                .map_err(|error| error.message)?;
            self.release(worker);

            Ok(Box::new(SupervisedEvaluator {
                supervisor: Arc::clone(self),
                checksum,
                material: Arc::new(material),
                identities: policies.iter().map(|policy| policy.id.clone()).collect(),
            }))
        }

        /// One frame about a compiled partition, compiling it first where this worker does not
        /// hold it — and once more when the worker answers that it no longer does.
        fn ask(
            self: &Arc<Self>,
            checksum: &str,
            material: &[u8],
            frame: &Cbor,
            deadline: Instant,
        ) -> Result<Cbor, WorkerError> {
            let mut worker = self.worker(deadline)?;
            for _ in 0..2 {
                if !worker.compiled.contains(checksum) {
                    match self.compile_in(&mut worker, checksum, material, deadline, true) {
                        Ok(()) => {}
                        // Still compiling at the deadline: this request is answered late, and the
                        // compile is left to finish, so the next request finds the program rather
                        // than killing it mid-compile again.
                        Err(error) if error.is_late() => {
                            self.finish_in_background(
                                worker,
                                Pending::Compile(checksum.to_owned()),
                            );
                            return Err(error);
                        }
                        Err(error) => return Err(error),
                    }
                }
                match exchange(&mut worker, frame, deadline) {
                    Exchange::Reply(reply) if text(&reply, "op").as_deref() == Some("missing") => {
                        worker.compiled.remove(checksum);
                    }
                    Exchange::Reply(reply) => {
                        self.release(worker);
                        return Ok(reply);
                    }
                    Exchange::Late => {
                        return Err(WorkerError::late(
                            "the worker did not answer before the deadline and was stopped",
                        ));
                    }
                    Exchange::Broken(why) => {
                        return Err(WorkerError::broken(format!("the worker stopped: {why}")));
                    }
                }
            }
            Err(WorkerError::broken(
                "the worker lost the partition it had just compiled".to_owned(),
            ))
        }

        fn evaluate(self: &Arc<Self>, checksum: &str, material: &[u8], query: &Query) -> Verdict {
            let deadline = query
                .deadline
                .unwrap_or_else(|| Instant::now() + self.limits.wall_clock);
            let frame = map(&[
                ("op", Cbor::Text("evaluate".into())),
                ("checksum", Cbor::Text(checksum.to_owned())),
                ("query", Cbor::Bytes(encode_query(query))),
                (
                    "remaining_ms",
                    Cbor::Int(
                        i64::try_from(
                            deadline
                                .saturating_duration_since(Instant::now())
                                .as_millis(),
                        )
                        .unwrap_or(i64::MAX),
                    ),
                ),
            ]);
            match self.ask(checksum, material, &frame, deadline) {
                Ok(reply) => match text(&reply, "op").as_deref() {
                    Some("verdict") => {
                        match bytes(&reply, "verdict").map(|held| decode_verdict(&held)) {
                            Some(Ok(verdict)) => verdict,
                            _ => Verdict::panicked(
                                "the worker answered a verdict that does not decode",
                            ),
                        }
                    }
                    _ => Verdict::panicked(format!(
                        "the worker answered out of protocol: {}",
                        text(&reply, "message").unwrap_or_default()
                    )),
                },
                Err(error) => error.into_verdict(),
            }
        }

        /// The partition's input check, in its worker, by `deadline`: `Ok(Ok(()))` admits the
        /// input, `Ok(Err(why))` refuses it, `Err(why)` is a check the worker could not run — the
        /// partition failing, never the caller's mistake.
        fn check_input(
            self: &Arc<Self>,
            checksum: &str,
            material: &[u8],
            input: &PartitionData,
            deadline: Option<Instant>,
        ) -> Result<Result<(), String>, String> {
            let frame = map(&[
                ("op", Cbor::Text("check_input".into())),
                ("checksum", Cbor::Text(checksum.to_owned())),
                ("input", Cbor::Bytes(encode_input(input))),
            ]);
            let deadline = deadline.unwrap_or_else(|| Instant::now() + self.limits.wall_clock);
            match self.ask(checksum, material, &frame, deadline) {
                Ok(reply) if text(&reply, "op").as_deref() == Some("checked") => Ok(Ok(())),
                Ok(reply) if text(&reply, "code").as_deref() == Some("input_refused") => {
                    Ok(Err(text(&reply, "message").unwrap_or_default()))
                }
                Ok(reply) => Err(format!(
                    "the worker answered the input check out of protocol: {}",
                    text(&reply, "message").unwrap_or_default()
                )),
                Err(error) => Err(error.message),
            }
        }

        fn compile_in(
            self: &Arc<Self>,
            worker: &mut Worker,
            checksum: &str,
            material: &[u8],
            deadline: Instant,
            finish_in_background: bool,
        ) -> Result<(), WorkerError> {
            let frame = map(&[
                ("op", Cbor::Text("compile".into())),
                ("language", Cbor::Text(self.language.clone())),
                ("checksum", Cbor::Text(checksum.to_owned())),
                ("partition", Cbor::Bytes(material.to_vec())),
            ]);
            if write_frame(&mut worker.input, &frame).is_err() {
                return Err(WorkerError::broken(
                    "the worker's input is closed".to_owned(),
                ));
            }
            match wait(worker, deadline, !finish_in_background) {
                Exchange::Reply(reply) if text(&reply, "op").as_deref() == Some("compiled") => {
                    worker.holds(checksum);
                    Ok(())
                }
                Exchange::Reply(reply)
                    if text(&reply, "code").as_deref() == Some("compile_refused") =>
                {
                    Err(WorkerError::refused(
                        text(&reply, "message").unwrap_or_default(),
                    ))
                }
                Exchange::Reply(reply) => Err(WorkerError::broken(format!(
                    "the worker refused the partition: {}",
                    text(&reply, "message").unwrap_or_default()
                ))),
                Exchange::Late => Err(WorkerError::late(
                    "the worker had not compiled the partition by the deadline",
                )),
                Exchange::Broken(why) => {
                    Err(WorkerError::broken(format!("the worker stopped: {why}")))
                }
            }
        }

        /// An idle worker, a new one while fewer than `size` are alive, or the first to come back
        /// before `deadline`.
        ///
        /// The live count is taken first and the idle list under it, everywhere, and a release
        /// notifies while it holds the count: a waiter cannot miss a worker that came back between
        /// its look at the idle list and its wait.
        fn worker(self: &Arc<Self>, deadline: Instant) -> Result<Worker, WorkerError> {
            let Ok(mut count) = self.live.count.lock() else {
                return Err(WorkerError::broken(
                    "the worker pool is poisoned".to_owned(),
                ));
            };
            loop {
                if let Some(worker) = self.idle.lock().ok().and_then(|mut idle| idle.pop()) {
                    return Ok(worker);
                }
                if *count < self.size {
                    *count += 1;
                    drop(count);
                    return self.start(deadline);
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(WorkerError::late("no worker was free before the deadline"));
                }
                // Woken when a worker is released or retired; the loop takes it or starts one.
                count = match self.live.freed.wait_timeout(count, left) {
                    Ok((count, _)) => count,
                    Err(_) => {
                        return Err(WorkerError::broken(
                            "the worker pool is poisoned".to_owned(),
                        ));
                    }
                };
            }
        }

        /// Returns a worker to the pool, or retires it: when the pool is full, or when its busy time
        /// has reached half its CPU budget, so the OS limit never stops a healthy worker
        /// mid-evaluation.
        ///
        /// The busy time bounds the CPU a single-threaded engine used; an engine that runs threads
        /// of its own can use more, and its `RLIMIT_CPU` stays the hard stop.
        fn release(&self, worker: Worker) {
            let budget = self
                .limits
                .cpu_seconds
                .map(|seconds| Duration::from_secs(seconds / 2));
            if budget.is_some_and(|budget| worker.busy >= budget) {
                return;
            }
            let Ok(count) = self.live.count.lock() else {
                return;
            };
            let kept = match self.idle.lock() {
                Ok(mut idle) if idle.len() < self.size => {
                    idle.push(worker);
                    None
                }
                _ => Some(worker),
            };
            self.live.freed.notify_one();
            drop(count);
            // Retired outside the locks: dropping a worker takes the count itself.
            drop(kept);
        }

        /// Hands a worker whose answer is still coming to a thread that waits for it — up to the
        /// wall clock — and then returns it to the pool, still counted alive meanwhile. A worker
        /// with an answer pending is never put back idle: its next frame would read the old one.
        fn finish_in_background(self: &Arc<Self>, mut worker: Worker, pending: Pending) {
            let supervisor = Arc::clone(self);
            let _ = std::thread::Builder::new()
                .name("permguard-worker-warm".to_owned())
                .spawn(move || {
                    let until = Instant::now() + supervisor.limits.wall_clock;
                    let Exchange::Reply(reply) = wait(&mut worker, until, true) else {
                        return;
                    };
                    let ready = match &pending {
                        Pending::Hello => {
                            text(&reply, "descriptor").as_deref()
                                == Some(supervisor.descriptor.as_str())
                        }
                        Pending::Compile(checksum) => {
                            let compiled = text(&reply, "op").as_deref() == Some("compiled");
                            if compiled {
                                worker.holds(checksum);
                            }
                            compiled
                        }
                    };
                    if ready {
                        supervisor.release(worker);
                    }
                });
        }

        /// Starts a worker; the caller has counted it alive.
        fn start(self: &Arc<Self>, deadline: Instant) -> Result<Worker, WorkerError> {
            let uncount = || {
                if let Ok(mut count) = self.live.count.lock() {
                    *count = count.saturating_sub(1);
                }
                self.live.freed.notify_one();
            };
            let mut command = Command::new(&self.executable);
            command
                .arg(WORKER_ARGUMENT)
                .args(&self.arguments)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                // A worker's diagnostics are an engine's words, which can carry tenant data: they
                // do not reach this process's logs.
                .stderr(Stdio::null())
                // Least privilege: none of this process's environment — credentials and settings
                // included — reaches the engine.
                .env_clear();
            limit(&mut command, self.limits);
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    uncount();
                    return Err(WorkerError::broken(format!(
                        "a worker could not be started: {error}"
                    )));
                }
            };
            let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
                let _ = child.kill();
                let _ = child.wait();
                uncount();
                return Err(WorkerError::broken(
                    "a worker started without its pipes".to_owned(),
                ));
            };
            // One frame in flight at a time, so a worker that misbehaves cannot queue frames here.
            let (sender, replies) = std::sync::mpsc::sync_channel(1);
            let mut worker = Worker {
                child,
                input: BufWriter::new(input),
                replies,
                compiled: HashSet::new(),
                busy: Duration::ZERO,
                live: Arc::clone(&self.live),
            };
            let reader = std::thread::Builder::new()
                .name("permguard-worker-reader".to_owned())
                .spawn(move || {
                    let mut output = BufReader::new(output);
                    loop {
                        let frame = read_frame(&mut output);
                        let end = !matches!(frame, Ok(Some(_)));
                        let sent = match frame {
                            Ok(Some(frame)) => sender.send(Ok(frame)),
                            Ok(None) => sender.send(Err("the worker closed its output".to_owned())),
                            Err(why) => sender.send(Err(why)),
                        };
                        if end || sent.is_err() {
                            return;
                        }
                    }
                });
            if let Err(error) = reader {
                return Err(WorkerError::broken(format!(
                    "a worker's reader could not be started: {error}"
                )));
            }

            // The runtime it carries must be the one this process describes: a binary replaced on
            // disk since this process started would otherwise answer with another engine.
            let hello = map(&[
                ("op", Cbor::Text("hello".into())),
                ("language", Cbor::Text(self.language.clone())),
            ]);
            let first = deadline.min(Instant::now() + self.limits.wall_clock);
            if write_frame(&mut worker.input, &hello).is_err() {
                return Err(WorkerError::broken(
                    "a worker's input closed before its first frame".to_owned(),
                ));
            }
            match wait(&mut worker, first, false) {
                Exchange::Reply(reply)
                    if text(&reply, "descriptor").as_deref() == Some(self.descriptor.as_str()) =>
                {
                    Ok(worker)
                }
                Exchange::Reply(_) => Err(WorkerError::refused(format!(
                    "the worker's `{}` is not the runtime this process describes",
                    self.language
                ))),
                // A worker still starting at this request's deadline finishes starting in the
                // background, so a pool of short deadlines still warms.
                Exchange::Late => {
                    self.finish_in_background(worker, Pending::Hello);
                    Err(WorkerError::late(
                        "a worker did not answer its first frame before the deadline",
                    ))
                }
                Exchange::Broken(why) => Err(WorkerError::broken(format!(
                    "a worker stopped at its first frame: {why}"
                ))),
            }
        }
    }

    /// The executable this process runs: `/proc/self/exe` on Linux, which names it even after the
    /// file on disk was replaced.
    fn own_executable() -> Result<PathBuf, Refused> {
        let proc_self = PathBuf::from("/proc/self/exe");
        if cfg!(target_os = "linux") && proc_self.exists() {
            return Ok(proc_self);
        }
        std::env::current_exe()
            .map_err(|error| Refused(format!("this process cannot name its executable: {error}")))
    }

    /// One frame out, one frame back, before the deadline — or the worker is killed.
    fn exchange(worker: &mut Worker, frame: &Cbor, deadline: Instant) -> Exchange {
        if write_frame(&mut worker.input, frame).is_err() {
            return Exchange::Broken("its input is closed".to_owned());
        }
        wait(worker, deadline, true)
    }

    /// One frame back before the deadline. Past it the worker is killed, unless `kill` is false.
    fn wait(worker: &mut Worker, deadline: Instant, kill: bool) -> Exchange {
        let started = Instant::now();
        let left = deadline.saturating_duration_since(started);
        let answer = worker.replies.recv_timeout(left);
        worker.busy += started.elapsed();
        match answer {
            Ok(Ok(reply)) => Exchange::Reply(reply),
            Ok(Err(why)) => Exchange::Broken(why),
            Err(RecvTimeoutError::Timeout) => {
                if kill {
                    let _ = worker.child.kill();
                }
                Exchange::Late
            }
            Err(RecvTimeoutError::Disconnected) => Exchange::Broken("its reader ended".to_owned()),
        }
    }

    /// Applies the OS limits in the child, after `fork` and before `exec`: the worker runs no
    /// engine code — no code of its own at all — before they hold.
    fn limit(command: &mut Command, limits: Limits) {
        use std::os::unix::process::CommandExt as _;

        let address_space = limits.address_space;
        let cpu = limits.cpu_seconds;
        // SAFETY: the closure runs in the forked child before `exec`. It calls only `setrlimit`,
        // which is async-signal-safe, allocates nothing and touches no lock.
        unsafe {
            command.pre_exec(move || {
                let set = |resource, value: u64| {
                    let limit = libc::rlimit {
                        rlim_cur: value as libc::rlim_t,
                        rlim_max: value as libc::rlim_t,
                    };
                    if libc::setrlimit(resource, &limit) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                };
                // A worker that dies never writes the policies and requests it held to a core
                // file.
                set(libc::RLIMIT_CORE, 0)?;
                #[cfg(any(target_os = "linux", target_os = "android"))]
                if let Some(bytes) = address_space {
                    set(libc::RLIMIT_AS, bytes)?;
                }
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                let _ = address_space;
                if let Some(seconds) = cpu {
                    set(libc::RLIMIT_CPU, seconds)?;
                }
                Ok(())
            });
        }
    }

    /// A partition compiled in a worker.
    struct SupervisedEvaluator {
        supervisor: Arc<Supervisor>,
        checksum: String,
        material: Arc<Vec<u8>>,
        identities: Vec<String>,
    }

    impl Evaluator for SupervisedEvaluator {
        fn evaluate(&self, query: &Query) -> Verdict {
            self.supervisor
                .evaluate(&self.checksum, &self.material, query)
        }

        /// The partition's own input check, run where the partition is compiled: a runtime moved
        /// into a worker keeps refusing an input its schema does not admit.
        fn check_input(&self, input: &PartitionData) -> Result<(), String> {
            self.check_input_by(input, None).unwrap_or_else(Err)
        }

        fn check_input_by(
            &self,
            input: &PartitionData,
            deadline: Option<Instant>,
        ) -> Result<Result<(), String>, String> {
            self.supervisor
                .check_input(&self.checksum, &self.material, input, deadline)
        }

        /// What this process keeps: the partition's bytes, kept to compile it again in a new
        /// worker. The engine's own memory is the worker's, bounded by its `RLIMIT_AS`.
        fn footprint(&self) -> usize {
            self.material.len()
        }

        fn policies(&self) -> Vec<String> {
            self.identities.clone()
        }
    }
}

// ─── frames ──────────────────────────────────────────────────────────────────────────────────────

/// Reads one frame; `None` at a clean end of input.
pub fn read_frame(input: &mut dyn Read) -> Result<Option<Cbor>, String> {
    let mut length = [0u8; 4];
    match input.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.to_string()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(format!(
            "a frame of {length} bytes is over the {MAX_FRAME}-byte bound"
        ));
    }
    let mut body = vec![0u8; length];
    input
        .read_exact(&mut body)
        .map_err(|error| error.to_string())?;
    cbor::decode_canonical(&body)
        .map(Some)
        .map_err(|error| format!("a frame is not canonical CBOR: {error:?}"))
}

/// Writes one frame.
pub fn write_frame(output: &mut dyn Write, frame: &Cbor) -> Result<(), String> {
    let body = cbor::encode(frame).map_err(|error| format!("{error:?}"))?;
    let length = u32::try_from(body.len()).map_err(|_| "a frame too large to send".to_owned())?;
    output
        .write_all(&length.to_be_bytes())
        .and_then(|()| output.write_all(&body))
        .and_then(|()| output.flush())
        .map_err(|error| error.to_string())
}

fn map(pairs: &[(&str, Cbor)]) -> Cbor {
    Cbor::Map(
        pairs
            .iter()
            .map(|(key, value)| (Cbor::Text((*key).to_owned()), value.clone()))
            .collect(),
    )
}

fn refused(code: &str, message: &str) -> Cbor {
    map(&[
        ("op", Cbor::Text("refused".into())),
        ("code", Cbor::Text(code.to_owned())),
        ("message", Cbor::Text(message.to_owned())),
    ])
}

fn field<'a>(frame: &'a Cbor, name: &str) -> Option<&'a Cbor> {
    let Cbor::Map(pairs) = frame else {
        return None;
    };
    pairs
        .iter()
        .find(|(key, _)| matches!(key, Cbor::Text(held) if held == name))
        .map(|(_, value)| value)
}

fn text(frame: &Cbor, name: &str) -> Option<String> {
    match field(frame, name)? {
        Cbor::Text(held) => Some(held.clone()),
        _ => None,
    }
}

fn bytes(frame: &Cbor, name: &str) -> Option<Vec<u8>> {
    match field(frame, name)? {
        Cbor::Bytes(held) => Some(held.clone()),
        _ => None,
    }
}

fn int(frame: &Cbor, name: &str) -> Option<i64> {
    match field(frame, name)? {
        Cbor::Int(held) => Some(*held),
        _ => None,
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        // Writing to a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

// ─── payloads ────────────────────────────────────────────────────────────────────────────────────

/// A partition as canonical CBOR: its policies and its artifacts, in a fixed order.
fn encode_material(policies: &[StoredPolicy], artifacts: &Artifacts) -> Vec<u8> {
    let policies = policies
        .iter()
        .map(|policy| {
            let mut pairs = vec![
                ("id", Cbor::Text(policy.id.clone())),
                ("source", Cbor::Bytes(policy.source.clone())),
            ];
            if let Some(alias) = &policy.alias {
                pairs.push(("alias", Cbor::Text(alias.clone())));
            }
            map(&pairs)
        })
        .collect();
    let mut held = Vec::new();
    for type_name in artifacts.types() {
        for blob in artifacts.all(type_name) {
            held.push(map(&[
                ("type", Cbor::Text(type_name.to_owned())),
                ("name", Cbor::Text(blob.name.clone())),
                ("media_type", Cbor::Text(blob.media_type.clone())),
                ("data", Cbor::Bytes(blob.data.clone())),
            ]));
        }
    }
    // Every member is text, bytes or an array of maps of those, each key named once: encoding
    // cannot fail.
    cbor::encode(&map(&[
        ("policies", Cbor::Array(policies)),
        ("artifacts", Cbor::Array(held)),
    ]))
    .unwrap_or_default()
}

fn decode_material(material: &[u8]) -> Result<(Vec<StoredPolicy>, Artifacts), ()> {
    let value = cbor::decode_canonical(material).map_err(|_| ())?;
    let (Some(Cbor::Array(policies)), Some(Cbor::Array(held))) =
        (field(&value, "policies"), field(&value, "artifacts"))
    else {
        return Err(());
    };
    let policies = policies
        .iter()
        .map(|policy| {
            Ok(StoredPolicy {
                id: text(policy, "id").ok_or(())?,
                alias: text(policy, "alias"),
                source: bytes(policy, "source").ok_or(())?,
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let mut artifacts = Artifacts::default();
    for blob in held {
        let artifact = artifact_type(&text(blob, "type").ok_or(())?).ok_or(())?;
        artifacts.insert(
            artifact,
            ArtifactBlob {
                name: text(blob, "name").ok_or(())?,
                media_type: text(blob, "media_type").ok_or(())?,
                data: bytes(blob, "data").ok_or(())?,
            },
        );
    }

    Ok((policies, artifacts))
}

fn entity_json(entity: &Entity) -> Value {
    serde_json::json!({"kind": entity.kind, "id": entity.id, "properties": entity.properties})
}

/// A partition's input as JSON: `{kind, data}`.
fn input_json(input: &PartitionData) -> Value {
    match input {
        PartitionData::Absent => serde_json::json!({"kind": "absent"}),
        PartitionData::CedarEntities(items) => {
            serde_json::json!({"kind": "cedar_entities", "data": items.as_slice()})
        }
        PartitionData::RegoData(data) => {
            serde_json::json!({"kind": "rego_data", "data": data.as_ref()})
        }
    }
}

fn input_from(value: &Value) -> Result<PartitionData, ()> {
    match value["kind"].as_str() {
        Some("cedar_entities") => Ok(PartitionData::CedarEntities(Arc::new(
            value["data"].as_array().cloned().ok_or(())?,
        ))),
        Some("rego_data") => Ok(PartitionData::RegoData(Arc::new(
            value["data"].as_object().cloned().unwrap_or_default(),
        ))),
        Some("absent") => Ok(PartitionData::Absent),
        _ => Err(()),
    }
}

fn encode_input(input: &PartitionData) -> Vec<u8> {
    serde_json::to_vec(&input_json(input)).unwrap_or_default()
}

fn decode_input(bytes: &[u8]) -> Result<PartitionData, ()> {
    input_from(&serde_json::from_slice(bytes).map_err(|_| ())?)
}

fn encode_query(query: &Query) -> Vec<u8> {
    let input = input_json(&query.input);
    let value = serde_json::json!({
        "subject": entity_json(&query.subject),
        "resource": entity_json(&query.resource),
        "action": {"name": query.action.name, "properties": query.action.properties},
        "context": query.context,
        "input": input,
    });
    serde_json::to_vec(&value).unwrap_or_default()
}

fn decode_query(bytes: &[u8], remaining_ms: Option<i64>) -> Result<Query, ()> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let entity = |held: &Value| -> Result<Entity, ()> {
        Ok(Entity {
            kind: held["kind"].as_str().ok_or(())?.to_owned(),
            id: held["id"].as_str().ok_or(())?.to_owned(),
            properties: held["properties"].as_object().cloned().unwrap_or_default(),
        })
    };
    let object =
        |held: &Value| -> Map<String, Value> { held.as_object().cloned().unwrap_or_default() };
    let input = input_from(&value["input"])?;

    Ok(Query {
        subject: entity(&value["subject"])?,
        resource: entity(&value["resource"])?,
        action: Action {
            name: value["action"]["name"].as_str().ok_or(())?.to_owned(),
            properties: object(&value["action"]["properties"]),
        },
        context: object(&value["context"]),
        deadline: remaining_ms
            .and_then(|millis| u64::try_from(millis).ok())
            .map(|millis| Instant::now() + Duration::from_millis(millis)),
        input,
    })
}

fn error_json(error: &EvaluationError) -> Value {
    serde_json::json!({"code": error.code, "message": error.message})
}

fn encode_verdict(verdict: &Verdict) -> Vec<u8> {
    let value = match verdict {
        Verdict::Permit { determining } => {
            serde_json::json!({"kind": "permit", "determining": determining})
        }
        Verdict::Deny {
            determining,
            beside,
        } => serde_json::json!({
            "kind": "deny",
            "determining": determining,
            "beside": beside.as_ref().map(error_json),
        }),
        Verdict::Abstain => serde_json::json!({"kind": "abstain"}),
        Verdict::Error { code, message } => {
            serde_json::json!({"kind": "error", "code": code, "message": message})
        }
    };
    serde_json::to_vec(&value).unwrap_or_default()
}

/// A verdict back from a worker, rebuilt through the constructors: a code the worker names that
/// is not one of the four causes is read as the engine failing, never trusted as a new one.
fn decode_verdict(bytes: &[u8]) -> Result<Verdict, ()> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let names = |held: &Value| -> Vec<String> {
        held.as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let failure = |code: &str, message: String| -> Verdict {
        use permguard_core::codes::pdp_native;
        match code {
            pdp_native::EVALUATION_DEADLINE_EXCEEDED => Verdict::deadline_exceeded(message),
            pdp_native::EVALUATION_PANICKED => Verdict::panicked(message),
            pdp_native::EVALUATION_INPUT_REJECTED => Verdict::input_rejected(message),
            _ => Verdict::engine_failed(message),
        }
    };
    let message = |held: &Value| held["message"].as_str().unwrap_or_default().to_owned();

    match value["kind"].as_str() {
        Some("permit") => Ok(Verdict::permit(names(&value["determining"]))),
        Some("deny") => {
            let denied = Verdict::deny(names(&value["determining"]));
            Ok(match value.get("beside").filter(|held| !held.is_null()) {
                Some(beside) => denied.despite(failure(
                    beside["code"].as_str().unwrap_or_default(),
                    message(beside),
                )),
                None => denied,
            })
        }
        Some("abstain") => Ok(Verdict::abstain()),
        Some("error") => Ok(failure(
            value["code"].as_str().unwrap_or_default(),
            message(&value),
        )),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_verdict_survives_the_round_trip_and_an_unknown_code_is_read_as_a_failure() {
        for verdict in [
            Verdict::permit(vec!["p".to_owned()]),
            Verdict::deny(vec!["d".to_owned()]),
            Verdict::deny_despite_failure(vec!["d".to_owned()], "beside"),
            Verdict::abstain(),
            Verdict::deadline_exceeded("late"),
            Verdict::input_rejected("bad"),
        ] {
            assert_eq!(decode_verdict(&encode_verdict(&verdict)), Ok(verdict));
        }
        let invented = br#"{"kind": "error", "code": "a_code_nobody_registered", "message": "m"}"#;
        assert_eq!(
            decode_verdict(invented)
                .expect("it decodes")
                .error()
                .map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_FAILED)
        );
        let unattributed = br#"{"kind": "deny", "determining": []}"#;
        assert_eq!(
            decode_verdict(unattributed),
            Ok(Verdict::Abstain),
            "through the constructors"
        );
    }

    #[test]
    fn a_query_survives_the_round_trip() {
        let mut query = Query::default();
        query.subject.kind = "User".to_owned();
        query.subject.id = "alice".to_owned();
        query.action.name = "read".to_owned();
        query
            .context
            .insert("ratio".to_owned(), serde_json::json!(0.25));
        query.input = PartitionData::RegoData(Arc::new(
            serde_json::json!({"tags": ["a"]})
                .as_object()
                .cloned()
                .expect("an object"),
        ));

        let back = decode_query(&encode_query(&query), Some(1_000)).expect("it decodes");
        assert_eq!(back.subject, query.subject);
        assert_eq!(back.action, query.action);
        assert_eq!(back.context, query.context, "a float travels as JSON");
        assert_eq!(back.input.rego_data(), query.input.rego_data());
        assert!(back.deadline.is_some());
    }

    #[test]
    fn a_frame_over_the_bound_or_not_canonical_is_refused() {
        let mut over = Vec::new();
        over.extend_from_slice(&u32::try_from(MAX_FRAME + 1).expect("fits").to_be_bytes());
        assert!(read_frame(&mut over.as_slice()).is_err());

        // A map whose keys are out of order is not canonical.
        let mut unsorted = vec![0, 0, 0, 5];
        unsorted.extend_from_slice(&[0xa2, 0x01, 0x01, 0x00, 0x00]);
        assert!(read_frame(&mut unsorted.as_slice()).is_err());

        let mut empty: &[u8] = &[];
        assert_eq!(read_frame(&mut empty), Ok(None), "a clean end of input");
    }

    #[test]
    fn a_partition_survives_the_round_trip() {
        let policies = vec![StoredPolicy {
            id: "p1".to_owned(),
            alias: Some("readers".to_owned()),
            source: b"permit (principal, action, resource);".to_vec(),
        }];
        let artifacts =
            Artifacts::just(crate::cedar::SCHEMA_ARTIFACT, b"entity User;").expect("registered");
        let (back, held) =
            decode_material(&encode_material(&policies, &artifacts)).expect("it decodes");
        assert_eq!(back, policies);
        assert_eq!(held, artifacts);
    }
}
