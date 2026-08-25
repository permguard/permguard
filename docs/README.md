<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Documentation

| Page | What is in it |
| --- | --- |
| [Quick start](quick-start.md) | Start a runtime and call it — plain, TLS, and mutual TLS, with the binary, `task` or `make` |
| [The command line](cli.md) | `permguard version`, `config`, `inspect`; how settings are resolved, and what the exit statuses mean |
| [Running the planes](running.md) | Ports, protocols, TLS per surface, and what each plane answers |
| [Deployment](deployment.md) | The legal shapes, every port by binary, discovery endpoints, and the signing rings |
| [Observability](observability.md) | Health, readiness, every metric, and the local Prometheus + Grafana + Loki lab |
| [Containers](docker.md) | The published images, and the compose lab |
| [Kubernetes](kubernetes.md) | The Helm chart, and the two defaults to change before production |
| [Git-like storage](gitlike-object-model.md) | The git-like store — object model, ids, media types, signatures, and the NOTP transfer protocol (draft specification) |
| [CLI workspace](cli-workspace.md) | Authoring locally: the `.permguard` layout, policies-not-files, every command, and the Cedar + Rego flows |
| [PDP lab](../pdp-lab/README.md) | A ready-made workspace — Cedar and Rego side by side — with the full CLI walkthrough |
| [Profiles & Manifest](profiles-manifest.md) | What a ledger declares (manifest, version semantics, the load gate) and how it is consumed (profiles, the `permguard.pdp.v1` contract) |
| [Answering decisions](authorization-check.md) | The decision endpoint: the volume walk, the in-memory cache and its bounds, the load gate and the block file, both languages, and `permguard check` |
| [Decision logs](decision-logs.md) | **Design**: where every decision is recorded — the spool, the signed shipping, the append-only store, the offset-based reading, and how GDPR is met rather than mentioned |
| [Keeping a data plane current](data-plane-mirrors.md) | The synchronization loop: what it follows, what it guarantees, and what it reports |
| [Security posture](security.md) | What is defended, what is delegated, and the constraints future work must respect |
| [Load testing](benchmarking.md) | The k6 benchmarks, the capacity and shed profiles, and the load-test dashboard |
| [Releasing](release.md) | What a tag produces, and where it goes |

Alongside these, in the repository root:

- [CHANGELOG.md](../CHANGELOG.md) — what changed, for somebody running it
- [COMPATIBILITY.md](../COMPATIBILITY.md) — what a version promises, and what it does not
- [CONTRIBUTING.md](../CONTRIBUTING.md) — how to work on it
- [SECURITY.md](../SECURITY.md) — how to report a vulnerability
