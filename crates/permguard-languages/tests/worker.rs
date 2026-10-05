// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The supervised worker, end to end: this test binary is its own worker.
//!
//! Run without the test harness, because the binary has two lives. Started with the worker
//! argument it serves frames against a test runtime whose policies say what to do — answer, sleep
//! past the deadline, panic, allocate past the address-space limit — and exits. Started plainly it
//! is the supervisor, and drives each fault through a real child process.

#![allow(clippy::expect_used, clippy::print_stdout, clippy::print_stderr)]

#[cfg(unix)]
mod harness;

#[cfg(unix)]
mod unix {
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    use permguard_languages::artifact::Artifacts;
    use permguard_languages::evaluate::{Evaluating, Evaluator, Query, StoredPolicy, Verdict};
    use permguard_languages::worker::{
        Catalogue, Limits, Supervisor, read_frame, serve, write_frame,
    };

    /// What a test policy does when it is evaluated: its source says.
    struct Scripted {
        behaviour: String,
        id: String,
    }

    impl Evaluator for Scripted {
        fn evaluate(&self, _query: &Query) -> Verdict {
            match self.behaviour.as_str() {
                "sleep" => {
                    std::thread::sleep(Duration::from_secs(30));
                    Verdict::permit(vec![self.id.clone()])
                }
                "panic" => panic!("a test engine came apart"),
                "allocate" => {
                    // Far past the limit the supervisor set, and touched so it is really used.
                    let mut held = vec![0u8; 3 * 1024 * 1024 * 1024];
                    held[0] = 1;
                    let last = held.len() - 1;
                    held[last] = 1;
                    Verdict::permit(vec![format!("{}", held.len())])
                }
                "stdout" => {
                    println!("an engine writing to standard output");
                    Verdict::permit(vec![self.id.clone()])
                }
                "pid" => Verdict::permit(vec![std::process::id().to_string()]),
                "pause" => {
                    std::thread::sleep(Duration::from_millis(300));
                    Verdict::permit(vec![self.id.clone()])
                }
                "core" => {
                    let mut limit = libc::rlimit {
                        rlim_cur: 1,
                        rlim_max: 1,
                    };
                    // SAFETY: `getrlimit` writes the struct it is handed and nothing else.
                    let read = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
                    Verdict::permit(vec![format!("{read}:{}", limit.rlim_cur)])
                }
                _ => Verdict::permit(vec![self.id.clone()]),
            }
        }
        fn check_input(&self, input: &permguard_languages::PartitionData) -> Result<(), String> {
            match input.rego_data() {
                Some(data) if data.contains_key("bad") => {
                    Err("the test schema refuses `bad`".to_owned())
                }
                _ => Ok(()),
            }
        }
        fn footprint(&self) -> usize {
            0
        }
        fn policies(&self) -> Vec<String> {
            vec![self.id.clone()]
        }
    }

    struct Runtime;

    impl Evaluating for Runtime {
        fn compile(
            &self,
            policies: &[StoredPolicy],
            _artifacts: &Artifacts,
        ) -> Result<Box<dyn Evaluator>, String> {
            let policy = policies.first().ok_or("no policy")?;
            let behaviour = String::from_utf8_lossy(&policy.source)
                .split('#')
                .next()
                .unwrap_or_default()
                .to_owned();
            match behaviour.as_str() {
                "refuse" => return Err("this test policy refuses to compile".to_owned()),
                "slowcompile" => std::thread::sleep(Duration::from_millis(600)),
                "diecompile" => panic!("a test compiler came apart"),
                "allocatecompile" => {
                    let mut held = vec![0u8; 3 * 1024 * 1024 * 1024];
                    let last = held.len() - 1;
                    held[last] = 1;
                }
                _ => {}
            }
            Ok(Box::new(Scripted {
                behaviour,
                id: policy.id.clone(),
            }))
        }
    }

    /// The worker's catalogue: one test runtime, under a fixed descriptor digest.
    struct Tests(&'static str);

    impl Catalogue for Tests {
        fn evaluating(&self, name: &str) -> Option<&dyn Evaluating> {
            (name == "test-runtime").then_some(&Runtime as &dyn Evaluating)
        }
        fn descriptor_digest(&self, name: &str) -> Option<String> {
            (name == "test-runtime").then(|| self.0.to_owned())
        }
    }

    const DIGEST: &str = "sha256:test-runtime";

    fn policy(source: &str) -> StoredPolicy {
        StoredPolicy {
            id: format!("p-{source}"),
            alias: None,
            source: source.as_bytes().to_vec(),
        }
    }

    fn supervisor(limits: Limits) -> std::sync::Arc<Supervisor> {
        Supervisor::with_executable(
            std::env::current_exe().expect("this binary names itself"),
            Vec::new(),
            "test-runtime",
            limits,
            2,
            &Tests(DIGEST),
        )
        .expect("a supervisor")
    }

    fn compiled(supervisor: &std::sync::Arc<Supervisor>, source: &str) -> Box<dyn Evaluator> {
        supervisor
            .compile(&[policy(source)], &Artifacts::default())
            .expect("the worker compiles it")
    }

    fn within(milliseconds: u64) -> Query {
        Query {
            deadline: Some(Instant::now() + Duration::from_millis(milliseconds)),
            ..Query::default()
        }
    }

    fn code(verdict: &Verdict) -> Option<&'static str> {
        verdict.error().map(|error| error.code)
    }

    /// The worker answers, and keeps answering on a reused process.
    fn answers() -> bool {
        let supervisor = supervisor(Limits::default());
        let program = compiled(&supervisor, "permit");
        for _ in 0..3 {
            assert_eq!(
                program.evaluate(&within(5_000)),
                Verdict::permit(vec!["p-permit".to_owned()])
            );
        }
        true
    }

    /// A partition the runtime refuses is refused at compile, as in-process.
    fn a_refused_compile_is_refused_at_load() -> bool {
        let supervisor = supervisor(Limits::default());
        let refused = supervisor
            .compile(&[policy("refuse")], &Artifacts::default())
            .err()
            .expect("refused");
        assert!(refused.contains("refuses to compile"), "{refused}");
        true
    }

    /// Past the deadline the worker is killed: `evaluation_deadline_exceeded`, promptly, and the
    /// next evaluation gets a fresh worker.
    fn a_worker_past_its_deadline_is_killed_and_replaced() -> bool {
        let supervisor = supervisor(Limits::default());
        let sleeping = compiled(&supervisor, "sleep");
        let started = Instant::now();
        let verdict = sleeping.evaluate(&within(300));
        assert_eq!(
            code(&verdict),
            Some(permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED),
            "{verdict:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "killed at the deadline"
        );

        let answering = compiled(&supervisor, "permit");
        assert!(
            answering.evaluate(&within(5_000)).permitted(),
            "a fresh worker answers"
        );
        true
    }

    /// A worker that panics is replaced: `evaluation_panicked`, and the next evaluation answers.
    fn a_worker_that_panics_is_replaced() -> bool {
        let supervisor = supervisor(Limits::default());
        let panicking = compiled(&supervisor, "panic");
        let verdict = panicking.evaluate(&within(5_000));
        assert_eq!(
            code(&verdict),
            Some(permguard_core::codes::pdp_native::EVALUATION_PANICKED),
            "{verdict:?}"
        );
        assert!(
            compiled(&supervisor, "permit")
                .evaluate(&within(5_000))
                .permitted()
        );
        true
    }

    /// Memory pressure: past `RLIMIT_AS` the worker's allocation fails and the process dies —
    /// `evaluation_panicked`, never a verdict. Linux enforces the limit; macOS does not.
    fn a_worker_over_its_address_space_dies_and_is_replaced() -> bool {
        if !cfg!(target_os = "linux") {
            println!("  (RLIMIT_AS is not enforced on this platform)");
            return false;
        }
        let supervisor = supervisor(Limits {
            address_space: Some(512 * 1024 * 1024),
            ..Limits::default()
        });
        let greedy = compiled(&supervisor, "allocate");
        let verdict = greedy.evaluate(&within(10_000));
        assert_eq!(
            code(&verdict),
            Some(permguard_core::codes::pdp_native::EVALUATION_PANICKED),
            "{verdict:?}"
        );
        true
    }

    /// A worker whose runtime is not the one this process describes is refused before it compiles
    /// anything.
    fn a_worker_with_another_runtime_is_refused() -> bool {
        let supervisor = Supervisor::with_executable(
            std::env::current_exe().expect("this binary names itself"),
            Vec::new(),
            "test-runtime",
            Limits::default(),
            1,
            &Tests("sha256:another-build"),
        )
        .expect("a supervisor");
        let refused = supervisor
            .compile(&[policy("permit")], &Artifacts::default())
            .err()
            .expect("refused");
        assert!(
            refused.contains("not the runtime this process describes"),
            "{refused}"
        );
        true
    }

    /// A worker clears its programs past its bound, and the supervisor forgets them with it: the
    /// first partition, evicted, is compiled again rather than answered as a failure.
    fn a_program_the_worker_evicted_is_compiled_again() -> bool {
        let supervisor = Supervisor::with_executable(
            std::env::current_exe().expect("this binary names itself"),
            Vec::new(),
            "test-runtime",
            Limits::default(),
            1,
            &Tests(DIGEST),
        )
        .expect("a supervisor");
        let first = compiled(&supervisor, "permit#0");
        for index in 1..=64 {
            compiled(&supervisor, &format!("permit#{index}"));
        }
        assert!(
            first.evaluate(&within(10_000)).permitted(),
            "compiled again, not failed"
        );
        true
    }

    /// The pool is bounded: with one worker, two evaluations at once take turns rather than start
    /// a second process.
    fn the_pool_never_runs_more_workers_than_its_size() -> bool {
        let supervisor = Supervisor::with_executable(
            std::env::current_exe().expect("this binary names itself"),
            Vec::new(),
            "test-runtime",
            Limits::default(),
            1,
            &Tests(DIGEST),
        )
        .expect("a supervisor");
        let pausing: std::sync::Arc<dyn Evaluator> =
            std::sync::Arc::from(compiled(&supervisor, "pause"));
        let started = Instant::now();
        let both: Vec<_> = (0..2)
            .map(|_| {
                let pausing = std::sync::Arc::clone(&pausing);
                std::thread::spawn(move || pausing.evaluate(&within(10_000)))
            })
            .collect();
        for held in both {
            assert!(held.join().expect("the thread finishes").permitted());
        }
        assert!(
            started.elapsed() >= Duration::from_millis(600),
            "one worker answered both, one after the other: {:?}",
            started.elapsed()
        );
        true
    }

    /// The partition's input check runs in its worker: a runtime moved there keeps refusing an
    /// input its schema does not admit.
    fn the_input_check_runs_in_the_worker() -> bool {
        let supervisor = supervisor(Limits::default());
        let program = compiled(&supervisor, "permit");
        let document = |key: &str| {
            permguard_languages::PartitionData::RegoData(std::sync::Arc::new(
                [(key.to_owned(), serde_json::Value::Bool(true))]
                    .into_iter()
                    .collect(),
            ))
        };
        assert!(program.check_input(&document("good")).is_ok());
        let refused = program.check_input(&document("bad")).expect_err("refused");
        assert!(refused.contains("refuses `bad`"), "{refused}");
        // A check the worker could not run in time is the partition failing, never a refusal of
        // the input: the outer error, which a plane answers as `evaluation_indeterminate`.
        let late = program.check_input_by(&document("good"), Some(Instant::now()));
        assert!(late.is_err(), "{late:?}");
        assert_eq!(
            program.check_input_by(
                &document("bad"),
                Some(Instant::now() + Duration::from_secs(5))
            ),
            Ok(Err("the test schema refuses `bad`".to_owned())),
            "an input refused is the inner error"
        );
        true
    }

    /// A worker runs with `RLIMIT_CORE` 0: one that dies writes no core file.
    fn a_worker_writes_no_core_file() -> bool {
        let supervisor = supervisor(Limits::default());
        let program = compiled(&supervisor, "core");
        let verdict = program.evaluate(&within(5_000));
        assert_eq!(verdict.determining(), ["0:0".to_owned()], "{verdict:?}");
        true
    }

    /// An engine writing to standard output writes to nothing: the frames travel on a private
    /// descriptor, and the protocol survives.
    fn an_engine_writing_to_standard_output_does_not_corrupt_the_protocol() -> bool {
        let supervisor = supervisor(Limits::default());
        let talkative = compiled(&supervisor, "stdout");
        for _ in 0..2 {
            assert!(talkative.evaluate(&within(5_000)).permitted());
        }
        true
    }

    /// A worker is retired once its busy time reaches half its CPU budget, so the OS limit never
    /// stops a healthy worker in the middle of an evaluation: the next call is a new process.
    fn a_worker_is_retired_before_its_cpu_budget() -> bool {
        let supervisor = Supervisor::with_executable(
            std::env::current_exe().expect("this binary names itself"),
            Vec::new(),
            "test-runtime",
            Limits {
                cpu_seconds: Some(1),
                ..Limits::default()
            },
            1,
            &Tests(DIGEST),
        )
        .expect("a supervisor");
        let pid = compiled(&supervisor, "pid");
        let pause = compiled(&supervisor, "pause");
        let first = pid.evaluate(&within(5_000)).determining().to_vec();
        for _ in 0..2 {
            assert!(pause.evaluate(&within(5_000)).permitted());
        }
        let second = pid.evaluate(&within(5_000)).determining().to_vec();
        assert_ne!(
            first, second,
            "a new worker answered after the old one was retired"
        );
        true
    }

    /// A cold compile still running at a request's deadline answers that request late and
    /// finishes in the background: the next request finds the program instead of killing the
    /// compile again.
    fn a_cold_compile_past_the_deadline_finishes_in_the_background() -> bool {
        let supervisor = Supervisor::with_executable(
            std::env::current_exe().expect("this binary names itself"),
            Vec::new(),
            "test-runtime",
            Limits::default(),
            1,
            &Tests(DIGEST),
        )
        .expect("a supervisor");
        let slow = compiled(&supervisor, "slowcompile");
        // Sixty-four more partitions push the slow one out of the only worker.
        for index in 0..64 {
            compiled(&supervisor, &format!("permit#{index}"));
        }
        let verdict = slow.evaluate(&within(100));
        assert_eq!(
            code(&verdict),
            Some(permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED),
            "{verdict:?}"
        );
        std::thread::sleep(Duration::from_millis(1_500));
        assert!(
            slow.evaluate(&within(200)).permitted(),
            "the compile finished in the background and the worker came back holding it"
        );
        true
    }

    /// A compile that kills the worker is refused at load, never served.
    fn a_compile_that_kills_the_worker_is_refused_at_load() -> bool {
        let supervisor = supervisor(Limits::default());
        let refused = supervisor
            .compile(&[policy("diecompile")], &Artifacts::default())
            .err()
            .expect("refused");
        assert!(refused.contains("stopped"), "{refused}");
        true
    }

    /// Memory pressure at compile: past `RLIMIT_AS` the worker dies and the load is refused.
    /// Linux enforces the limit; macOS does not.
    fn a_compile_over_its_address_space_is_refused_at_load() -> bool {
        if !cfg!(target_os = "linux") {
            println!("  (RLIMIT_AS is not enforced on this platform)");
            return false;
        }
        let supervisor = supervisor(Limits {
            address_space: Some(512 * 1024 * 1024),
            ..Limits::default()
        });
        assert!(
            supervisor
                .compile(&[policy("allocatecompile")], &Artifacts::default())
                .is_err()
        );
        true
    }

    /// Corrupted-cache fault: a compile frame whose bytes do not match their checksum is refused by
    /// the worker, never compiled under the wrong name.
    fn a_partition_that_does_not_match_its_checksum_is_refused() -> bool {
        use permguard_objects::cbor::Value as Cbor;

        let frame = Cbor::Map(vec![
            (Cbor::Text("op".into()), Cbor::Text("compile".into())),
            (
                Cbor::Text("language".into()),
                Cbor::Text("test-runtime".into()),
            ),
            (Cbor::Text("checksum".into()), Cbor::Text("00".repeat(32))),
            (
                Cbor::Text("partition".into()),
                Cbor::Bytes(b"not what the checksum names".to_vec()),
            ),
        ]);
        let mut input = Vec::new();
        write_frame(&mut input, &frame).expect("framed");
        let mut output = Vec::new();
        assert_eq!(serve(&Tests(DIGEST), &mut input.as_slice(), &mut output), 0);

        let reply = read_frame(&mut output.as_slice())
            .expect("a frame")
            .expect("one reply");
        let Cbor::Map(pairs) = reply else {
            panic!("a map");
        };
        assert!(
            pairs.iter().any(|(key, value)| {
                *key == Cbor::Text("code".into())
                    && *value == Cbor::Text("checksum_mismatch".into())
            }),
            "{pairs:?}"
        );
        true
    }

    use super::harness::Case;

    pub fn main() -> ExitCode {
        if permguard_languages::worker::started_as_worker() {
            // The production path: frames on a private descriptor, standard output pointed away.
            std::process::exit(permguard_languages::worker::serve_on_protocol(&Tests(
                DIGEST,
            )));
        }

        let cases: [(&str, Case); 16] = [
            ("answers", answers),
            (
                "a_refused_compile_is_refused_at_load",
                a_refused_compile_is_refused_at_load,
            ),
            (
                "a_worker_past_its_deadline_is_killed_and_replaced",
                a_worker_past_its_deadline_is_killed_and_replaced,
            ),
            (
                "a_worker_that_panics_is_replaced",
                a_worker_that_panics_is_replaced,
            ),
            (
                "a_worker_over_its_address_space_dies_and_is_replaced",
                a_worker_over_its_address_space_dies_and_is_replaced,
            ),
            (
                "a_worker_with_another_runtime_is_refused",
                a_worker_with_another_runtime_is_refused,
            ),
            (
                "a_partition_that_does_not_match_its_checksum_is_refused",
                a_partition_that_does_not_match_its_checksum_is_refused,
            ),
            (
                "a_program_the_worker_evicted_is_compiled_again",
                a_program_the_worker_evicted_is_compiled_again,
            ),
            (
                "the_pool_never_runs_more_workers_than_its_size",
                the_pool_never_runs_more_workers_than_its_size,
            ),
            (
                "the_input_check_runs_in_the_worker",
                the_input_check_runs_in_the_worker,
            ),
            ("a_worker_writes_no_core_file", a_worker_writes_no_core_file),
            (
                "an_engine_writing_to_standard_output_does_not_corrupt_the_protocol",
                an_engine_writing_to_standard_output_does_not_corrupt_the_protocol,
            ),
            (
                "a_worker_is_retired_before_its_cpu_budget",
                a_worker_is_retired_before_its_cpu_budget,
            ),
            (
                "a_cold_compile_past_the_deadline_finishes_in_the_background",
                a_cold_compile_past_the_deadline_finishes_in_the_background,
            ),
            (
                "a_compile_that_kills_the_worker_is_refused_at_load",
                a_compile_that_kills_the_worker_is_refused_at_load,
            ),
            (
                "a_compile_over_its_address_space_is_refused_at_load",
                a_compile_over_its_address_space_is_refused_at_load,
            ),
        ];

        super::harness::run(&cases)
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

#[cfg(not(unix))]
fn main() {
    println!("test result: ok. 0 passed; 0 failed (the supervised worker exists only on Unix)");
}
