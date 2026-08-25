<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Testing & coverage

How this repository is tested, how to run everything, and the coverage floor
every crate must hold. Status: **enforced** — the commands below are the ones
CI runs.

## The commands

| Command | What it runs |
| --- | --- |
| `task test` | every test of every crate |
| `task check` | lint + the structural checks + tests — what a change must pass |
| `task coverage` | measures coverage and **fails if any crate is under the 60% line floor** |
| `task coverage:html` | annotated-source HTML report, opened in the browser |
| `task coverage:lcov` | `lcov.info` for editors and CI uploaders |

Every `task x` has a `make x` twin (`coverage:html` → `make coverage-html`);
`scripts/check-build-systems.sh` keeps the two in step. Coverage needs
`cargo-llvm-cov` once: `cargo install cargo-llvm-cov`.

## The floor

```text
scripts/check-coverage.sh          measure, then gate
scripts/check-coverage.sh --report gate the last measurement (fast; run right after a measure)
```

**60% of lines, per crate.** Per crate and not per workspace on purpose: an
average lets a large well-tested crate hide an untested one. The floor is a
floor — being above it is expected, going below it is a failure, and raising
it is a one-line change in `scripts/check-coverage.sh`.

## How the tests are organized

| Layer | Where | What it proves |
| --- | --- | --- |
| Unit | `#[cfg(test)] mod tests` beside the code | one rule, one function, one rendering |
| Crate integration | `crates/<crate>/tests/*.rs` | the crate through its public seams |
| Binary integration | `crates/permguard-cli/tests/cli.rs` | the CLI **as the binary people run**: exit statuses, the three `-o` formats, the guards (lock, layout gate) — hermetic, offline |
| Server-shaped | `crates/permguard-cli/tests/stub_server.rs` | the HTTP client and the catalog commands against a canned server on a real socket — no server crates involved |
| Runtime smoke | `crates/permguard-all-in-one/tests/smoke.rs` | the composed binary starts, says `server.started` for both planes, and stops |
| Property tests | `crates/*/tests/*properties.rs` | canonical encoders, parsers and wire messages over generated input |
| Fuzz harnesses | `fuzz/fuzz_targets/*.rs` | parser entry points for `cargo fuzz`, kept outside the normal workspace build |

Conventions the suites follow:

- **Hermetic**: every test owns a scratch directory under the OS temp dir,
  keyed by pid and thread — suites run in parallel and never share state.
- **No network beyond loopback**, and no port numbers: anything that listens
  binds port `0` and reads back what it got.
- **The interface is the assertion**: exit statuses are documented in
  `permguard --help` and asserted literally; error sentences are asserted by
  the words an operator would search for.
- Test names read as statements: `a_held_lock_refuses_the_second_command…`.

The fuzz targets are opt-in:

```sh
cargo install cargo-fuzz
cargo fuzz run cbor_decode
cargo fuzz run manifest_decode
cargo fuzz run notp_decode
cargo fuzz run decision_json
```

## What is deliberately not unit-tested

The NOTP push/pull lifecycle against a real server, TLS/mTLS handshakes and
the gRPC transport end-to-end are covered by the lab walkthrough
([pdp-lab](../pdp-lab/README.md)) and the bench profiles — they need real
sockets, real keys and two processes, and pretending otherwise would test the
mocks. The in-process engine tests in `permguard-cli/tests/engine_e2e.rs`
cover the same protocol logic without the wire.
