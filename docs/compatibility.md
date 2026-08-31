<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compatibility and versioning

Permguard follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every crate in the
workspace carries the same version and moves together as one product.

## What a version promises

Below `1.0.0`, a minor release may break the interfaces below, with the change recorded in the
[changelog](../CHANGELOG.md). From `1.0.0`, breaking one requires a major release.

| Interface | Example | Where it is tested |
| --- | --- | --- |
| Configuration file keys | `controlPlane.public.http.addr` | plane and config tests |
| Environment variables | `PERMGUARD_CONTROL_HTTP_ADDR` | plane server tests |
| CLI commands, flags, settings, exit statuses and machine output | `permguard inspect --timeout` | `crates/permguard-cli/tests` |
| HTTP routes and JSON | `GET /version` | plane module tests |
| gRPC services and messages | `permguard.control.v1.ControlPlane` | `.proto` files |
| Native PDP contract | `POST /access/v1/evaluation` | data-plane tests |
| Temporal PDP contract | `POST /temporal/v1alpha1/events` | `temporal_events.rs` |
| Event log | `POST /events/v1alpha1/batches` | event-store tests |
| Discovery documents | `/.well-known/permguard-…-configuration` | module and discovery tests |
| Read offsets | opaque, signed, scope- and filter-bound | `permguard-stream` and store tests |
| Metric names and labels | `permguard_surface_requests_total` | telemetry tests |
| Container image names and tags | `permguard/all-in-one:0.1` | release configuration |

## Experimental interfaces

Names carrying `v1alpha1` are intentionally unstable. Their wire and replication shapes may change
in a minor release, including changes that require stored history to be rebuilt. They are served
only when the corresponding experimental feature and plane capability are both enabled.

Everything else in the table is covered normally, including settings and exit codes introduced by
experimental implementations.

## What a version does not promise

- Rust API stability between internal crates.
- Human-readable log wording; stable automation uses `event.name`.
- Error-detail prose; clients switch on the accompanying stable reason code.

## Collection endpoints

`zones list` and `ledgers list` return the complete collection. Adding optional pagination later is
an addition; imposing a default page size on the existing contract would be a breaking change.

## Deprecation

A configuration key, flag, or field that is going away is announced in the changelog, remains
working with a warning for at least one minor release, and is then recorded under *Removed*. A
renamed key retains its old name as an accepted alias for that period.

## Minimum supported Rust version

The MSRV is declared as `rust-version` in `Cargo.toml`, and CI builds with that exact version.
Raising it is a minor release and is recorded in the changelog.
