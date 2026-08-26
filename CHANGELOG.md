<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) as described in
[COMPATIBILITY.md](COMPATIBILITY.md).

Release notes on GitHub are generated from commit subjects. This file is the other half: what changed
for somebody *running* Permguard — a setting that moved, an exit status that gained a meaning, a
default that is no longer the same. A release cannot be cut without an entry here, and
`scripts/check-changelog.sh` is what enforces that.

## [Unreleased]

Nothing yet.

## [0.1.2] - 2026-08-26

### Fixed

- Container registries no longer expose Cosign's internal `sha256-*.sig` artifacts as broken image
  versions. Image provenance remains available through GitHub Artifact Attestations, while release
  checksums remain signed with Cosign.
- Homebrew publishes the current CLI as `permguard/tap/cli` and its versioned aliases as
  `cli@<version>` and `cli@<major>`, without leaking the implementation language into the cask name.

## [0.1.1] - 2026-08-26

### Fixed

- Container images reach Docker Hub again, alongside GHCR. The release logged in to Docker Hub and
  then pushed nowhere near it: no `images:` entry ever named it. Versioned tags only — `latest` and
  `0.0` on those names still carry the Go implementation, and move when it does.
- The Helm chart's default images exist. `registry: ghcr.io` used to render
  `ghcr.io/permguard/control-plane`, a name that was never published; the registry value carries the
  namespace now, so `docker.io/permguard` and `ghcr.io/permguard/permguard` both resolve.

### Added

- `scripts/prepare-release.sh` and the `Prepare Release` workflow move the version, the lock, the
  chart and the changelog together, and create the tag from the result — so a tag can no longer
  reach the release pipeline describing a version the commit does not contain.

## [0.1.0] - 2026-08-25

The first release of the Rust workspace: the shared infrastructure crates, the reusable plane
modules, the deployable binaries, the decision endpoint and the decision log.

Nothing before this was released *from this workspace*. The `v0.0.x` line is the Go
implementation living in the same repository, and this is a different product versioned from
zero — so everything below is an addition, including the entries that read as fixes: they
record decisions taken while this release was being built, kept because the reasoning is worth
more than the tidiness of dropping them.

### Added

- **Contracts crate** (`permguard-core`): storage, secrets, signing keys, audit, services and the
  server host, as traits and the types they exchange, with a dependency allowlist enforced by
  `scripts/check-core-dependencies.sh`.
- **Default implementations** (`permguard-std`), one Cargo feature per area, with `provision` — the
  one that can mint a certificate authority — deliberately outside the default set.
- **One listener for every surface** (`permguard-transport`): TCP, TLS, mutual TLS, certificate
  revocation, material reload, and a shutdown that drains connections in flight.
- **Telemetry surface** (`permguard-telemetry`) on a port of its own: `/healthz`, `/readyz` and
  `/metrics`, with liveness and readiness reported separately.
- **Control plane and data plane**, each serving `GET /`, `/version` and `/health` over HTTP and
  `GetInfo`/`GetHealth` over gRPC, and an all-in-one runtime that hosts both.
- **Command line** (`permguard`) with `version`, `config` and `inspect`:
  - `inspect` probes every plane and reports `ready`, `degraded`, `unhealthy` or `unreachable`,
    each with a stable `reason` code, a latency and a UTC timestamp;
  - `config show`/`get`/`set`/`reset` over `~/.permguard/config.yml`, resolved through four layers —
    flag, environment, file, default — with `show` reporting which layer each value came from;
  - TLS and mutual TLS against a plane, including a client identity for a server that asks for one.
- **Deployment**: multi-architecture images for the CLI, the all-in-one runtime and both planes,
  published to Docker Hub and the GitHub Container Registry; a Helm chart; and a local lab with
  Prometheus, Grafana and Loki already wired to the planes.

- **Per-address connection bound** (`limits.connections_per_peer`, default 256): one client can no
  longer hold a surface's whole connection pool while every global number reads as healthy. Addresses
  in `limits.peer_exempt` — a load balancer, a health checker; single IPs or CIDR blocks — skip the
  per-address bound and still count toward the pool. Behind a load balancer the address seen is the
  balancer's, so there either exempt it or set the bound to `0` and let the ingress do the counting.
- **Connection lifetime** (`limits.connection_lifetime`, default unbounded): a connection past it is
  ended, which is what lets a deployment behind a balancer rotate connections.
- **Write-stall bound** (`limits.write_stall_timeout`, default 30s): a response that makes no progress
  for that long — a client that stopped reading its answer — ends the connection instead of stalling
  in the peer's TCP window forever.

- **Peer authorisation** (`tls.allow`, per endpoint): of everybody the client authority signed, an
  endpoint now answers only the peers its allow list names — `cn:`, `dn:` or `sha256:` entries, one
  per line. An authenticated peer off the list gets `403` and a log record naming it. An empty or
  absent list keeps the previous behaviour: the handshake is the whole decision. Configuring a list
  on an endpoint that demands no client certificate is refused at startup.
- **Build disclosure switch** (`public.disclose_build`, default `true`): set `false` and `/version`
  and gRPC `GetInfo` stop naming the version and commit, keeping plane and product so
  `permguard inspect` still identifies what answered.
- **Request-head byte bound** (`limits.header_bytes`, default 64k), covering HTTP/1 and HTTP/2.
- **CRL expiry gauge** `permguard_tls_crl_expiry_timestamp_seconds`, with a lab alert at seven days.
- A startup warning when secrets resolve from the environment outside development mode.
- The Helm chart refuses at template time the shape that enables the all-in-one beside a
  standalone plane: the all-in-one is both planes in one process, and mixing them is two
  deployments fighting over one identity.
- `operations.audit.refusals` (default `false`): when on, denied catalog operations land on the
  audit trail as `<operation>.refused` with the stable error code — for deployments whose
  compliance regime wants denied attempts on the record. Internal faults never reach the trail.
- `permguard completion bash|zsh|fish` prints shell completions, and every leaf command's `--help`
  now carries worked examples.
- The CLI's `-o json`/`-o yaml` now shape errors too: a refusal lands on stderr as the same
  `{class, code, message}` triple the server answers, exit statuses unchanged.
- **One error shape for every API** — `{class, code, message}` on HTTP and gRPC alike, the class
  deciding both status codes, gRPC carrying class and code as metadata. How much an `internal`
  error discloses follows `public.error_detail` (`full`/`minimal`; unset, `development_mode`
  decides, minimal by default) — the server's log always keeps the full detail.
- **Zones and ledgers** on the control plane: create, list, get, rename and delete, served
  identically over HTTP (`/v1/zones…`) and gRPC (`permguard.control.v1.ZoneCatalog`), stored on the
  volume as GUID-named directories with plain-JSON indexes — atomic replace for readers, per-scope
  locks for writers. Ids are UUIDv7; names are strict, URL-safe, and unique in their scope (zones
  across the deployment, ledgers within their zone). The CLI grows `permguard zones …` and
  `permguard ledgers --zone <name-or-id> …`, and every reference accepts the name or the id. All
  mutations land in the audit trail.
- **Authorization decisions** on the data plane: the `permguard.pdp.v1` profile — OpenID AuthZEN
  1.0 with Permguard's extensions — served identically over HTTP
  (`POST /access/v1/evaluation`, `/access/v1/evaluations`,
  `GET /.well-known/authzen-configuration`) and gRPC
  (`permguard.data.v1.PolicyDecisionPoint`). `zone` and `ledger` are **required fields of the
  payload**, by name or by identity: one endpoint answers for every ledger a plane holds, and a
  request naming neither is refused with `400` rather than answered against a default. Boxcarring
  and the three `options.evaluations_semantic` values are implemented; the standard's Search APIs
  are not served, and their absence from the metadata document is the declaration. Both built-in
  languages answer the same contract — Cedar through `cedar-policy`, Rego through `regorus` with a
  written convention (`allow` permits, `deny` overrides, absent means no). A deny is a `200` with
  `decision: false`; a ledger this plane does not mirror is `404`; one it may not serve is `503`.
  Every decision, permit and deny alike, lands in the audit trail with the id its response carries.
- **Schema enforcement at load**: a partition that declares `schema: true` has every policy
  type-checked against it, in strict mode, when it is compiled — a policy that does not satisfy the
  schema refuses the load instead of being served. With a schema, the request itself is validated
  too, so an action or a context attribute the ledger never declared is refused rather than silently
  ignored. (The Go implementation did neither.)
- **The decision cache** (`dataPlane.authz.cache.partitions`, default 64;
  `dataPlane.authz.cache.bytes`, default 256M; `dataPlane.authz.max_evaluations`, default 256): a
  ledger's policies are read off the volume once, compiled, and kept, so a decision is answered out
  of memory. The commit is part of the cache key, so a synchronization that advances a ledger needs
  no flush and a replaced commit is never served; the synchronization loop compiles a freshly
  mirrored ledger itself, so the first request after a sync is as fast as the thousandth. Least
  recently used entries are dropped when either bound is reached.
- **Unserveable ledgers are remembered** (`<mirror>/BLOCKED`): a ledger whose manifest this engine is
  outside the range of — or whose schema is no longer satisfied — is refused once and then skipped
  for the cost of one file read per round, until its commit changes. Nothing to configure, and a
  restart does not forget. `permguard_authz_blocked_ledgers` is the gauge to alert on.
- **Mirroring for the data plane** (`dataPlane.mirrors`): a plane follows a list of exact server URLs,
  each with anchored zone and ledger patterns — naming neither means everything that server lists —
  and keeps `<volume>/mirrors/<zone-id>/<ledger-id>` current on a cadence (`interval`, default 30s;
  `timeout` per ledger, default 2m; `parallelism`; `jitter`). Rounds never overlap: a tick that finds
  the previous one working is skipped. A server that does not answer never causes a deletion; a
  mirror the configuration or the server no longer names is removed, behind three guards. Per-server
  TLS material (`mirrors.servers[].tls`) with no "skip verification" anywhere. Every round is audited,
  including the quiet ones.
- **`permguard check`**: ask a data plane for a decision — a document (`-f file`, `-f -` for standard
  input) or flags (`--subject user:alice --action read --resource document:budget`), in
  `terminal`/`json`/`yaml`. Which store the question is about follows one rule shared by every
  command: flags win, then the workspace, then the document's own `zone`/`ledger`
  (`--ignore-workspace` sends it as written). **A deny exits 0** — it is an answer; only a request
  that could not be evaluated is a failure.
- **What a control plane holds, as metrics**: `permguard_store_bytes`,
  `permguard_zone_bytes{zone}`, `permguard_ledger_bytes{zone,ledger}`, `_ledger_objects` and
  `_ledger_counter`, measured by a walk of the store once a minute rather than accumulated — so they
  are true when they are read, and reconcile with `du`. Both lab dashboards were extended: the
  control plane gains disk per zone, ledgers by size and growth over time; the data plane gains
  decisions, latency, cache hit rate and occupancy, blocked ledgers and mirror freshness.
- **Reclaiming what nothing references.** A content-addressed store only ever adds: a push that
  never commits leaves objects nothing will reach, and so does a history that moved past a policy
  version. Now both sides reclaim them, under one rule — *keep what any ref reaches, plus anything
  younger than the grace period*.
  - The control plane sweeps on a cadence (`controlPlane.storage.gc`: `enabled` default true,
    `interval` default 6h, `grace` default 24h). Every sweep is audited, including the quiet ones,
    and reports `permguard_gc_objects_removed_total`, `_bytes_reclaimed_total`, `_objects_retained`
    and `_sweeps_total`.
  - `permguard objects prune` does the same for a workspace mirror, keeping what the tracked
    checkpoint or the staged snapshot reaches. `--dry-run` reports what would go without touching
    anything; `terminal`, `json` and `yaml` like every other command.
  - **The grace period is a safety property, not a knob**: during a push the uploaded objects are
    legitimately unreachable, so a sweep that ignored their age would delete the work of every push
    in flight. Values below 15 minutes are refused at startup. On the client the workspace lock
    plays the same role, so no grace period is needed there.
  - A closure with a hole stops the sweep for that ledger (and refuses the client's prune, pointing
    at `permguard verify`): a walk that cannot be completed cannot tell "unreachable" from
    "unreachable *from here*".
- **Load-test suite** (`bench/`, k6): closed-loop ceiling, open-model latency ladder, shed
  behaviour, gRPC and TLS/mTLS runs, with `task bench:*` targets, capacity and shed server
  profiles, a Prometheus remote-write receiver in the lab, and a **Permguard · Load test**
  dashboard overlaying what the client felt with what the server measured.

### Fixed while building this release

- **A partition towards one control plane no longer costs it its mirrors.** With several servers
  configured, reaping was driven by whatever the *answering* servers listed, so a server that could
  not be reached had its ledgers deleted from the plane — the exact opposite of the rule the loop
  claims. Reaping now considers only mirrors attributable to a server that answered this round (the
  `LEDGER` file beside each mirror records which server put it there); a mirror that names no server
  is left in place and reported. The previous test only covered a single configured server, which is
  the case where the bug cannot appear.
- **gRPC refusals now carry the same class and code HTTP does.** A refusal read `… (grpc/NotFound)`
  over gRPC and `… (not_found/no_ref)` over HTTP, so a caller telling "this ref does not exist yet"
  from "this failed" by reading the code was right on one transport and wrong on the other —
  `permguard checkout` of an empty ledger failed over `grpc://` and succeeded over `http://`. Both
  now produce `sentence (class/code)`, taken from the metadata the server already sends.
- **A changed schema or manifest is no longer reported as "no changes".** The workspace plan compared
  policies only, so an edited `*.cedarschema` — or an edited `manifest.yml` — produced an empty plan
  and never reached the server. The plan now also compares the manifest digest and each partition's
  subtree, and reports what it found (`~ cedar/schema`, `~ manifest`).

### Decided while building this release

- **`dataPlane.sync` is now `dataPlane.mirrors`**, and its environment variables moved from
  `PERMGUARD_SYNC_*` to `PERMGUARD_MIRRORS_*`. The block is named after what it keeps current — the
  mirrors on the volume — rather than after the act of keeping them, which matters now that a second
  thing on this plane will also synchronise (the decision log shipper). The keys inside are
  unchanged. Metric and log-event names are untouched: `permguard_sync_*` describes the loop's activity, and
  renaming them would break dashboards and alerts for no gain.

- **Revocation-list expiry is now enforced**: a CRL past its `nextUpdate` refuses every mutual-TLS
  handshake instead of being trusted forever. The gauge above predicts the moment.
- The TLS reload watcher compares file digests instead of modification times, so a rewrite inside
  one clock tick — or a copy that preserves times — is still noticed.
- Every GitHub Actions step is pinned to a commit SHA rather than a movable tag.
- `permguard_surface_connections_refused_total` now carries a `scope` label — `pool` or `peer` —
  saying which bound refused. Queries that sum by `surface` are unaffected.

[Unreleased]: https://github.com/permguard/permguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/permguard/permguard/releases/tag/v0.1.0
