// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Deep verification: what startup does not read, checked in the background or on demand.
//!
//! | Check                        | Startup                                  | Here                     |
//! | ---------------------------- | ---------------------------------------- | ------------------------ |
//! | a journal's open tail        | yes: the last segment whole              | yes                      |
//! | a journal's older segments   | the header and the first frame           | every frame, in full     |
//! | index continuity, claims     | across first frames and the last segment | across every frame       |
//! | content-addressed objects    | no                                       | every file, or a sample  |
//!
//! Verification is read-only: a finding is reported, never repaired — a repair here would decide,
//! without the operator, which of two disagreeing copies of the truth is the right one. A [`Mode`]
//! reads every file, or a sample of them chosen from a seed, so successive sampled passes with new
//! seeds cover everything in time; a [`Budget`] bounds the bytes one pass reads.
//!
//! [`Background`] repeats sampled passes on a thread of its own, off every request path, and hands
//! each report to its caller, which logs the findings. A sample is drawn from each file's path:
//! relative to the tree for objects, as the journal's directory names it for segments. [`volume`] is the forensic entry point the
//! server binary's `volume verify` and the command line call: every journal below a volume root,
//! found by its segments, and every object tree its owner names.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use super::Dir;
use super::Result;

/// Which files a pass reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Every file.
    Full,
    /// About `per_mille` of every thousand files, chosen by `seed`. Every file has a fixed place
    /// among a thousand, from the digest of its path, and a seed selects a window of `per_mille`
    /// places that the next seed moves on by as many: consecutive seeds read different files, and
    /// `⌈1000 / per_mille⌉` consecutive seeds read every file.
    Sample { per_mille: u16, seed: u64 },
}

impl Mode {
    fn selects(&self, path: &Path) -> bool {
        match *self {
            Self::Full => true,
            Self::Sample { per_mille, seed } => {
                let place = u64::from(
                    u16::from_be_bytes({
                        let digest = Sha256::digest(path.as_os_str().as_encoded_bytes());
                        [digest[0], digest[1]]
                    }) % 1000,
                );
                let per_mille = u64::from(per_mille.min(1000));
                let start = seed.wrapping_mul(per_mille) % 1000;
                (place + 1000 - start) % 1000 < per_mille
            }
        }
    }
}

/// The bytes one pass may still read; `None` is unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget(Option<u64>);

impl Budget {
    /// No bound: a forensic check reads everything.
    pub fn unbounded() -> Self {
        Self(None)
    }

    /// At most `bytes`.
    pub fn bytes(bytes: u64) -> Self {
        Self(Some(bytes))
    }

    /// Spends `bytes`; `false` when they do not fit, and nothing is spent.
    fn spend(&mut self, bytes: u64) -> bool {
        match &mut self.0 {
            None => true,
            Some(left) if *left >= bytes => {
                *left -= bytes;
                true
            }
            Some(_) => false,
        }
    }
}

/// One thing verification found wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: PathBuf,
    pub what: String,
}

/// What a pass checked and found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    pub files_checked: u64,
    pub bytes_read: u64,
    pub findings: Vec<Finding>,
    /// Whether the pass read everything its mode selected: `false` when the budget ran out first.
    pub complete: bool,
}

impl Report {
    /// An empty report, complete until a budget runs out.
    pub fn new() -> Self {
        Self {
            complete: true,
            ..Self::default()
        }
    }

    fn found(&mut self, path: PathBuf, what: impl Into<String>) {
        self.findings.push(Finding {
            path,
            what: what.into(),
        });
    }

    /// Reads `path` within the budget: `None` when the budget is spent, which marks the report
    /// incomplete. The bytes count as read whatever the file turns out to be; the caller counts the
    /// file as checked once it judges it.
    fn read(&mut self, path: &Path, budget: &mut Budget) -> Option<std::io::Result<Vec<u8>>> {
        let length = std::fs::symlink_metadata(path).map_or(0, |metadata| metadata.len());
        if !budget.spend(length) {
            self.complete = false;
            return None;
        }
        self.bytes_read += length;
        Some(std::fs::read(path))
    }
}

/// Checks a journal of the storage library in `dir`, every frame of the segments `mode` selects.
///
/// Each selected segment must have a whole header and only whole frames, but for a torn tail of
/// the last; in [`Mode::Full`], every segment must start where the one before it ended, and claim
/// generations must never decrease across the whole journal. With the volume's `claim`, no frame
/// may carry a generation above it. A failure record the next open would apply is not read here.
pub fn journal(
    dir: &Dir,
    claim: Option<u64>,
    mode: Mode,
    budget: &mut Budget,
    report: &mut Report,
) -> Result<()> {
    let segments = super::journal::segment_names(dir)?;
    let count = segments.len();
    let mut expected: Option<u64> = Some(0);
    let mut highest = super::volume::UNCLAIMED;
    for (position, (first, name)) in segments.into_iter().enumerate() {
        let path = dir.child_path(&name);
        let last = position + 1 == count;
        if !mode.selects(&path) {
            // Continuity is unknown past a segment not read.
            expected = None;
            continue;
        }
        let Some(read) = report.read(&path, budget) else {
            return Ok(());
        };
        report.files_checked += 1;
        let bytes = match read {
            Ok(bytes) => bytes,
            Err(error) => {
                report.found(path, format!("unreadable: {error}"));
                expected = None;
                continue;
            }
        };
        if let Some(expected) = expected
            && first != expected
        {
            report.found(
                path.clone(),
                format!("starts at frame {first}, and the journal holds {expected} before it"),
            );
        }
        match super::journal::verify_segment(&bytes, first, &name, last) {
            Ok((frames, claims)) => {
                expected = expected.map(|_| first + frames);
                for (index, generation) in claims {
                    if let Some(claim) = claim
                        && generation > claim
                    {
                        report.found(
                            path.clone(),
                            format!(
                                "frame {index} carries claim generation {generation}, above the \
                                 volume's claim {claim}: the claim is behind the data"
                            ),
                        );
                    }
                    let claim = generation;
                    if matches!(mode, Mode::Full) && claim < highest {
                        report.found(
                            path.clone(),
                            format!(
                                "frame {index} carries claim generation {claim} after a frame of \
                                 generation {highest}: a stale writer"
                            ),
                        );
                    }
                    highest = highest.max(claim);
                }
            }
            Err(what) => {
                report.found(path, what);
                expected = None;
            }
        }
    }

    Ok(())
}

/// The check an owner gives for one file of its content-addressed tree: `Some(true)` when the file
/// holds what its name says, `Some(false)` when it does not, `None` when the file is not one of its
/// objects and is not counted.
pub type ObjectCheck = dyn Fn(&Path, &[u8]) -> Option<bool> + Send + Sync;

/// Checks every file below `root` that `mode` selects against `check`, which is given the file's
/// path relative to `root` and its bytes.
pub fn objects(
    root: &Path,
    check: &ObjectCheck,
    mode: Mode,
    budget: &mut Budget,
    report: &mut Report,
) -> Result<()> {
    walk(root, &mut |path| {
        let Ok(relative) = path.strip_prefix(root) else {
            return true;
        };
        if !mode.selects(relative) {
            return true;
        }
        let Some(read) = report.read(path, budget) else {
            return false;
        };
        match read {
            Ok(bytes) => match check(relative, &bytes) {
                Some(true) => report.files_checked += 1,
                Some(false) => {
                    report.files_checked += 1;
                    report.found(
                        path.to_path_buf(),
                        "does not hold what its name says: corrupted, left as it is",
                    );
                }
                // Not one of the owner's objects: neither checked nor counted.
                None => {}
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                report.files_checked += 1;
                report.found(path.to_path_buf(), format!("unreadable: {error}"));
            }
        }
        true
    })
}

/// The forensic check of a volume: every journal of the storage library below `root`, found by its
/// segments and judged against the volume's `claim`, and every object tree in `trees`, `(path
/// relative to root, its owner's check)`.
pub fn volume(
    root: &Path,
    claim: Option<u64>,
    trees: &[(PathBuf, Arc<ObjectCheck>)],
    mode: Mode,
    budget: &mut Budget,
) -> Result<Report> {
    let mut report = Report::new();
    let mut journals = Vec::new();
    walk_dirs(root, &mut |dir| match super::journal::segment_names(dir) {
        Ok(segments) if !segments.is_empty() => journals.push(dir.path().to_path_buf()),
        Ok(_) => {}
        // A segment name no journal writes: a journal that cannot even be listed is a finding.
        Err(error) => report.found(dir.path().to_path_buf(), error.to_string()),
    })?;
    for path in journals {
        journal(&Dir::open(&path)?, claim, mode, budget, &mut report)?;
    }
    for (tree, check) in trees {
        let path = root.join(tree);
        if path.is_dir() {
            objects(&path, check.as_ref(), mode, budget, &mut report)?;
        }
    }

    Ok(report)
}

/// Calls `visit` on every regular file below `root`, without following links, until it answers
/// `false`. Walked with an explicit stack, so a deep tree costs memory, not the thread's stack.
fn walk(root: &Path, visit: &mut dyn FnMut(&Path) -> bool) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let dir = match Dir::open(&directory) {
            Ok(dir) => dir,
            // Gone since it was listed: nothing to check.
            Err(_) if !directory.exists() => continue,
            Err(error) => return Err(error),
        };
        let mut names = dir.names()?;
        names.sort();
        for name in names {
            if !visit(&dir.child_path(&name)) {
                return Ok(());
            }
        }
        let mut subdirs = dir.subdirs()?;
        subdirs.sort();
        pending.extend(subdirs.into_iter().rev().map(|name| dir.child_path(&name)));
    }

    Ok(())
}

fn walk_dirs(root: &Path, visit: &mut dyn FnMut(&Dir)) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let dir = match Dir::open(&directory) {
            Ok(dir) => dir,
            Err(_) if !directory.exists() => continue,
            Err(error) => return Err(error),
        };
        visit(&dir);
        pending.extend(dir.subdirs()?.into_iter().map(|name| dir.child_path(&name)));
    }

    Ok(())
}

/// One pass of a background verification: given the mode and the budget, it answers the report.
pub type Pass = dyn Fn(Mode, &mut Budget) -> Report + Send + Sync;

/// Sampled passes, repeated on a thread of their own until stopped or dropped.
pub struct Background {
    stop: Arc<(Mutex<bool>, Condvar)>,
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Background {
    /// Runs `pass` every `interval`, each time on a new sample of `per_mille` (at least one, at most a
    /// thousand) and within `budget_bytes`, and hands each report to `report`. The first pass runs
    /// one interval after the start, so it does not compete with the start's own reads. A pass that
    /// panics is reported as incomplete, and the next one runs as usual.
    pub fn spawn(
        interval: Duration,
        per_mille: u16,
        budget_bytes: u64,
        pass: Arc<Pass>,
        report: Arc<dyn Fn(&Report) + Send + Sync>,
    ) -> std::io::Result<Self> {
        let per_mille = per_mille.clamp(1, 1000);
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let running = Arc::new(AtomicBool::new(true));
        let thread = {
            let stop = Arc::clone(&stop);
            let running = Arc::clone(&running);
            std::thread::Builder::new()
                .name("storage-verify".to_owned())
                .spawn(move || {
                    // Cleared however the thread ends.
                    struct Ended(Arc<AtomicBool>);
                    impl Drop for Ended {
                        fn drop(&mut self) {
                            self.0.store(false, Ordering::Release);
                        }
                    }
                    let _ended = Ended(running);
                    let mut seed = 0u64;
                    loop {
                        let (lock, wake) = &*stop;
                        let stopped = lock
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let (stopped, _) = wake
                            .wait_timeout_while(stopped, interval, |stopped| !*stopped)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if *stopped {
                            break;
                        }
                        drop(stopped);
                        let mut budget = Budget::bytes(budget_bytes);
                        let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            pass(Mode::Sample { per_mille, seed }, &mut budget)
                        }))
                        .unwrap_or_else(|_| Report::default());
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            report(&done)
                        }));
                        seed = seed.wrapping_add(1);
                    }
                })?
        };

        Ok(Self {
            stop,
            running,
            thread: Some(thread),
        })
    }

    /// Whether the thread still runs.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Stops the passes and waits for the one under way to finish.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        let (lock, wake) = &*self.stop;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        self.halt();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::storage::journal::{Journal, Options};

    fn scratch(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-verify-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    fn small() -> Options {
        Options {
            max_frame: 1024,
            segment_bytes: 200,
            ..Options::default()
        }
    }

    #[test]
    fn a_whole_journal_verifies_and_damage_in_an_old_segment_is_found_not_repaired() {
        let path = scratch("journal");
        let (mut journal, _) =
            Journal::open(Dir::open(&path).expect("dir"), small()).expect("opens");
        for index in 0..10u8 {
            journal.append(1, &[index; 60]).expect("appended");
        }
        drop(journal);
        let mut report = Report::new();
        super::journal(
            &Dir::open(&path).expect("dir"),
            None,
            Mode::Full,
            &mut Budget::unbounded(),
            &mut report,
        )
        .expect("verified");
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert!(report.files_checked >= 3, "several segments");

        // A byte flipped inside the second segment: startup does not read it, verification does.
        let mut names: Vec<_> = std::fs::read_dir(&path)
            .expect("listed")
            .map(|entry| entry.expect("entry").path())
            .collect();
        names.sort();
        let damaged = names[1].clone();
        let mut bytes = std::fs::read(&damaged).expect("read");
        let at = bytes.len() - 40;
        bytes[at] ^= 0xff;
        std::fs::write(&damaged, &bytes).expect("damaged");

        Journal::open(Dir::open(&path).expect("dir"), small())
            .expect("startup reads the last segment and the first frames only");
        let mut report = Report::new();
        super::journal(
            &Dir::open(&path).expect("dir"),
            None,
            Mode::Full,
            &mut Budget::unbounded(),
            &mut report,
        )
        .expect("verified");
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert_eq!(report.findings[0].path, damaged);
        assert_eq!(
            std::fs::read(&damaged).expect("read"),
            bytes,
            "never repaired"
        );
    }

    #[test]
    fn a_frame_above_the_volume_claim_is_found() {
        let path = scratch("behind");
        let (mut journal, _) = Journal::open(
            Dir::open(&path).expect("dir"),
            Options {
                claim: 5,
                ..small()
            },
        )
        .expect("opens");
        journal.append(1, b"x").expect("appended");
        drop(journal);
        let mut report = Report::new();
        super::journal(
            &Dir::open(&path).expect("dir"),
            Some(4),
            Mode::Full,
            &mut Budget::unbounded(),
            &mut report,
        )
        .expect("verified");
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(report.findings[0].what.contains("behind the data"));
    }

    #[test]
    fn a_pass_that_panics_does_not_stop_the_runner() {
        let reports = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&reports);
        let runner = Background::spawn(
            Duration::from_millis(5),
            0,
            1000,
            Arc::new(|mode, _budget: &mut Budget| match mode {
                Mode::Sample { seed: 0, .. } => panic!("a broken pass"),
                _ => Report::new(),
            }),
            Arc::new(move |report: &Report| seen.lock().expect("lock").push(report.complete)),
        )
        .expect("spawned");
        let started = std::time::Instant::now();
        while reports.lock().expect("lock").len() < 2 {
            assert!(started.elapsed() < Duration::from_secs(10), "passes go on");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(runner.is_running());
        runner.stop();
        let seen = reports.lock().expect("lock").clone();
        assert_eq!(
            &seen[..2],
            &[false, true],
            "the panic is an incomplete pass"
        );
    }

    #[test]
    fn a_corrupted_object_is_found_and_left_as_it_is() {
        let path = scratch("objects");
        for name in ["aa/one", "aa/two", "bb/three"] {
            let file = path.join(name);
            std::fs::create_dir_all(file.parent().expect("parent")).expect("fan");
            std::fs::write(&file, name.as_bytes()).expect("object");
        }
        std::fs::write(path.join("bb/three"), b"not three").expect("corrupted");
        let check =
            |relative: &Path, bytes: &[u8]| Some(relative.to_string_lossy().as_bytes() == bytes);
        let mut report = Report::new();
        objects(
            &path,
            &check,
            Mode::Full,
            &mut Budget::unbounded(),
            &mut report,
        )
        .expect("verified");
        assert_eq!(report.files_checked, 3);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, path.join("bb/three"));
        assert_eq!(
            std::fs::read(path.join("bb/three")).expect("read"),
            b"not three"
        );
    }

    #[test]
    fn samples_cover_everything_in_time_and_a_budget_bounds_a_pass() {
        let path = scratch("sample");
        for index in 0..200 {
            std::fs::write(path.join(format!("{index:03}")), [0u8; 10]).expect("file");
        }
        let check = |_: &Path, _: &[u8]| Some(true);
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..10 {
            let mut report = Report::new();
            let selected: Vec<_> = (0..200)
                .map(|index| PathBuf::from(format!("{index:03}")))
                .filter(|name| {
                    Mode::Sample {
                        per_mille: 100,
                        seed,
                    }
                    .selects(name)
                })
                .collect();
            objects(
                &path,
                &check,
                Mode::Sample {
                    per_mille: 100,
                    seed,
                },
                &mut Budget::unbounded(),
                &mut report,
            )
            .expect("verified");
            assert_eq!(report.files_checked as usize, selected.len());
            seen.extend(selected);
        }
        assert_eq!(
            seen.len(),
            200,
            "ten consecutive samples of a tenth cover every file"
        );

        let mut report = Report::new();
        objects(
            &path,
            &check,
            Mode::Full,
            &mut Budget::bytes(55),
            &mut report,
        )
        .expect("ran");
        assert_eq!(report.files_checked, 5, "55 bytes read five 10-byte files");
        assert!(!report.complete);
    }

    #[test]
    fn the_background_runner_repeats_passes_and_stops() {
        let passes = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&passes);
        let runner = Background::spawn(
            Duration::from_millis(5),
            10,
            1000,
            Arc::new(|mode, _budget: &mut Budget| {
                let mut report = Report::new();
                if let Mode::Sample { seed, .. } = mode {
                    report.files_checked = seed;
                }
                report
            }),
            Arc::new(move |report: &Report| {
                seen.lock().expect("lock").push(report.files_checked);
            }),
        )
        .expect("spawned");
        let started = std::time::Instant::now();
        while passes.lock().expect("lock").len() < 3 {
            assert!(started.elapsed() < Duration::from_secs(10), "passes repeat");
            std::thread::sleep(Duration::from_millis(2));
        }
        runner.stop();
        let seeds = passes.lock().expect("lock").clone();
        assert_eq!(&seeds[..3], &[0, 1, 2], "a new seed each pass");
    }
}
