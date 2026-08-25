<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Permguard

[![ci](https://github.com/permguard/permguard/actions/workflows/ci.yml/badge.svg)](https://github.com/permguard/permguard/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)

Permguard as a Rust workspace: shared infrastructure crates, reusable plane modules, and deployable
application binaries.

```sh
task run:all                 # or: make run-all
permguard inspect
```

```text
control plane
  endpoint: http://127.0.0.1:7556
  status:   ready
  health:   live=true ready=true
  latency:  0ms
...
2 of 2 planes ready, 2 reachable
```

Then, for a local environment that looks like a real one — Prometheus, Grafana and Loki, with
dashboards already provisioned:

```sh
task lab:up                  # Grafana on http://127.0.0.1:7590
```

## Documentation

| Page | What is in it |
| --- | --- |
| [Quick start](docs/quick-start.md) | Plain, TLS and mutual TLS, each with the binary, `task` and `make` |
| [The command line](docs/cli.md) | `version`, `config`, `inspect`, `check`; settings resolution and exit statuses |
| [Answering decisions](docs/authorization-check.md) | The `permguard.pdp.v1` endpoint: the volume walk, the in-memory cache, the load gate, both languages, and `permguard check` |
| [Decision logs](docs/decision-logs.md) | **Design**: where every decision is recorded, shipped, kept and consumed |
| [Keeping a data plane current](docs/data-plane-mirrors.md) | The synchronization loop: what it follows, what it guarantees, what it reports |
| [Running the planes](docs/running.md) | Ports, protocols, TLS per surface, and what each plane answers |
| [Observability](docs/observability.md) | Health, readiness, every metric, and the local monitoring lab |
| [Containers](docs/docker.md) | The published images, and the compose lab |
| [Kubernetes](docs/kubernetes.md) | The Helm chart, and what to change before production |
| [Releasing](docs/release.md) | What a tag produces, and where it goes |

## How it is put together

Three layers, and the boundaries between them are checked rather than hoped for.

| Crate | What it is |
| --- | --- |
| `permguard-core` | **The contracts**: storage, secrets, signing keys, audit, services, the server host. Traits and the types they exchange, no implementation, no socket, no runtime. |
| `permguard-std` | The default implementations, one Cargo feature per area. |
| `permguard-transport` | One listener for every surface: TCP, TLS, mutual TLS, revocation, reload, and a shutdown that drains. |
| `permguard-telemetry` | Liveness, readiness and metrics, on a port of its own. |
| `permguard-server` | The server host, its service registry, the command line that drives them — and `plane/`, the composition root: the one place that names a concrete storage, audit sink or signing ring. |
| `permguard-languages` | The built-in policy languages, compiled in: Cedar and Rego — **split by role**: the base both sides need (is this legal, what alias does the source declare), the authoring half only the CLI needs (splitting files), and the evaluating half only the data plane calls (compile once, then decide). It plugs *into* the model, never the other way round, so a language pack from anywhere needs no change to the model. |
| `permguard-objects` | What the objects **are**: canonical CBOR, digests, blob/tree/commit, policy identity, the manifest, signed head statements. Dependency-free — it knows no language, no protocol, no storage, which is what lets every side compute the same digests without agreeing on anything else. |
| `permguard-notp` | How the objects **move**: the Negotiated Object Transfer Protocol's wire messages, one encoder and one decoder shared by every party. |
| `permguard-control-client` | How a **client** reaches a Permguard deployment: endpoints and trust material, both transports, the catalog, the NOTP verbs, the decision endpoint, and the verified local mirror. The CLI and the data plane share it, so the two speak the wire identically. |
| `permguard-control-plane`, `permguard-data-plane`, `permguard-all-in-one` | The binaries. The control plane also owns the server half of NOTP (`engine`, `store`) and what it holds, measured (`inventory`); the data plane owns the mirroring loop (`sync`) and the decision endpoint (`authz`) — the `permguard.pdp.v1` profile over both transports. |
| `permguard-cli` | `permguard` — and `engine/`, which is both halves the CLI needs: the NOTP client (`transfer`) and authoring. |

A crate exists where a second consumer does. Where a thing has exactly one consumer it is a module
of that consumer — which is why the NOTP server half lives in the control plane, the client half in
the CLI, and each plane owns the `.proto` it serves (a caller generates its own client from that
file, so nothing depends backwards).

Two properties hold this together, and neither is expressible in the type system, so both are
enforced by a script that runs in CI:

- **`permguard-core` depends on four crates and no more** — whatever lands in its dependency list
  lands in every crate in the workspace, and a contracts crate that drags a database driver stops
  being a contracts crate. `scripts/check-core-dependencies.sh`.
- **No crate constructs its own collaborators.** A composition root is the single place that names a
  concrete implementation, which is what lets a different binary reuse the plane modules and supply
  its own. `scripts/check-composition-root.sh`.

## Load testing

```sh
task lab:observability        # Grafana + Prometheus, watching the plane you start next
task bench:server             # release build, limits out of the way — in another shell
task bench:peak               # the req/s ceiling
task bench:ladder             # latency at fixed rising rates, where the knee is
task bench:shed               # overload under default limits (against task run:control)
```

Server-side numbers land on **Permguard · Overview** with no flags at all; `task bench:grafana`
prints the k6 flags that put the client-side view beside them on **Permguard · Load test**. The whole
method — capacity vs shed profiles, open vs closed model, remote runs — is in
[docs/benchmarking.md](docs/benchmarking.md).

## Working on it

```sh
task check                   # or: make check — lint, structural checks, tests
task test PKG=permguard-cli
task lint
```

See [CONTRIBUTING.md](CONTRIBUTING.md), and [COMPATIBILITY.md](COMPATIBILITY.md) for what a version
promises — which is also the list of things a change has to be careful with.

## License

Apache-2.0. See [LICENSE](LICENSE).
