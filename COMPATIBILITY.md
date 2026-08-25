<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compatibility and versioning

Permguard is versioned with [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every crate
in the workspace carries the same version and moves together: they are one product, released from one
tag, and a build combining two of them from different releases is not something anybody tests.

## What a version promises

Below `1.0.0`, a **minor** release may break any of the interfaces below, and the change is recorded
in [CHANGELOG.md](CHANGELOG.md) under *Changed* or *Removed*. From `1.0.0`, breaking any of them
requires a major release.

These are the interfaces. They are what somebody automates against, so they are what a version has to
be about:

| Interface | Example | Where it is tested |
| --- | --- | --- |
| Configuration file keys | `controlPlane.public.http.addr` | plane and config tests |
| Environment variables | `PERMGUARD_CONTROL_HTTP_ADDR` | plane server tests |
| CLI commands, flags and settings | `permguard inspect --timeout` | `crates/permguard-cli/tests` |
| CLI exit statuses | `0`, `1`, `2`, `64`, `70` | `crates/permguard-cli/tests` |
| Machine-readable output fields | `status`, `reason`, `latency_ms` | `crates/permguard-cli/tests` |
| HTTP routes and their JSON | `GET /version` | plane module tests |
| gRPC services and messages | `permguard.control.v1.ControlPlane`, `permguard.data.v1.PolicyDecisionPoint` | `.proto` files |
| The decision contract | `POST /access/v1/evaluation` and its `{decision, context}` — the `permguard.pdp.v1` profile | `crates/permguard-data-plane/tests` |
| Metric names and labels | `permguard_surface_requests_total{surface,method,status}` | telemetry tests |
| Container image names and tags | `permguard/all-in-one:0.1` | release configuration |

## What a version does not promise

- **Rust API stability.** The crates are published as one product, not as libraries; `permguard-core`
  is a contract between crates in this workspace, and a build outside it should pin an exact version.
- **Log message wording.** Records carry a stable `event.name` — that is the field to match on. The
  human-readable message beside it is free to be reworded.
- **The wording of a `detail` string.** Every `detail` in a report is paired with a `reason` code, and
  the code is the interface. A runbook that matches on English prose is a runbook that breaks on a
  typo fix.

## List endpoints return everything

`zones list` and `ledgers list` — the HTTP and gRPC calls beneath them included — return the whole
collection, deliberately: the catalog is designed for hundreds of entries, and pagination against
hundreds is machinery without a customer. This is recorded so the future stays cheap: a `--limit`
or a page token added later is an **addition**, not a break — whereas a default page size imposed on
an endpoint that used to return everything would be a break, and will not happen without a major.

## Deprecation

A configuration key, flag or field that is going away is:

1. announced in [CHANGELOG.md](CHANGELOG.md) under *Deprecated*, in a release that still supports it;
2. kept working for at least one minor release, warning on stderr when it is used;
3. removed in a release that records it under *Removed*.

A key that is renamed keeps its old name as an accepted alias for that period, rather than failing.

## Minimum supported Rust version

The MSRV is declared as `rust-version` in `Cargo.toml`, and CI builds with exactly that version —
both on every pull request and again on the tagged commit before anything is published. Building with
the minimum is what makes it a fact rather than a claim: a job on `stable` passes while the declared
minimum quietly stops compiling.

There is deliberately no `rust-toolchain.toml`. Pinning the toolchain in the repository makes every
`cargo` invocation on every machine fetch a second copy of the same compiler, and fails outright on a
machine that cannot reach `static.rust-lang.org`. The pin lives where builds that ship happen — the
workflows — and a developer uses the stable toolchain they already have.

Raising the MSRV is a **minor** release, recorded in the changelog: a toolchain nobody can install is
a break like any other.
