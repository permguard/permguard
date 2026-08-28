<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) as described in
[COMPATIBILITY.md](COMPATIBILITY.md).

Release notes on GitHub are generated from commit subjects. This file is the other half: what changed
for somebody *running* Permguard — a setting that moved, an exit status that gained a meaning, a
default that is no longer the same. Nothing enforces it: write the bullets under *Unreleased* while
the change is fresh, and `scripts/prepare-release.sh` gives them their version number when a release
is cut.

## [Unreleased]

Nothing yet.

## [0.1.5] - 2026-08-28

### Changed — breaking, pre-release

- **A plane publishes where it is reached, not where it binds.** `public.http.advertised_url` is
  the address the discovery documents name; absent, the bind address is used as before. This was a
  real defect on Kubernetes: a pod binds `0.0.0.0` because it has to, and every document this
  deployment served named `http://0.0.0.0:7656` — an address a listener understands and nothing can
  dial. The chart now sets it to the Service DNS by default and takes an override for an Ingress or
  a load balancer. A plane that binds a wildcard and was told nothing to advertise warns at
  startup, beside the line that says where it is listening.

- **One source for the published URL, scheme included.** The PDP document used to derive `http` vs
  `https` from the *global* TLS setting while the listener bound with the *plane's own*, so a data
  plane serving HTTPS could publish `http://` endpoints. Both documents now come from the same
  function, and the scheme from that endpoint's own TLS.

- **`permguard.pdp.v1` is named as what it is: Permguard's own interface.** It is not an
  implementation of, nor a compatibility claim for, any other authorization API, and the code and
  documentation no longer say otherwise. The shape will look familiar, because that is the obvious
  shape for the question; what changes is that the contract is Permguard's to specify and to
  evolve, without anyone having to ask whether somebody else's document still holds.

  - The discovery endpoint is now `GET /.well-known/permguard-pdp-v1-configuration`. The old path
    is **not mounted** and answers `404`.
  - The document is Permguard's own, identified by `interface: "permguard.pdp.v1"`, with
    `endpoints`, `capabilities` and `store_scope` — no longer borrowing another specification's
    field names.
  - Capabilities are namespaced `urn:permguard:pdp:v1:*`. Each names something implemented, tested,
    and answered identically over HTTP and gRPC.
  - A data plane's own `/.well-known/server-configuration` now carries `interfaces`, linking to the
    configuration above — so a client is given one URL and finds the rest.
  - Over gRPC, `GetMetadata` becomes `GetConfiguration` and returns the same document field for
    field.

- **`entities` is replaced by `partition_inputs`.** A request used to carry one entity graph for the
  whole profile, addressed to a *runtime*. That is unanswerable the moment a profile holds two
  partitions of the same runtime with different schemas: a graph legal for one is refused by the
  other, so the shape only ever worked while all but one partition ignored it. An input is now
  addressed to a **partition by name**, which is the only identity that separates them.

  ```json
  "partition_inputs": {
    "admin-cedar": { "type": "permguard.cedar.entities.v1", "data": [ … ] },
    "admin-rego":  { "type": "permguard.rego.data.v1",      "data": { … } }
  }
  ```

  `entities` is **refused**, never ignored — `field_removed`, on every binding, including gRPC,
  whose schema has no field to carry it and would otherwise have dropped it silently. The proto
  tags and names are reserved so nothing can be given them later.

- **A ledger declares what each partition accepts**, in `manifest.yml`:

  ```yaml
  admin-cedar:
    input: { type: permguard.cedar.entities.v1, required: true }
  ```

  The types are a fixed registry this build implements — `permguard.cedar.entities.v1` (a Cedar
  entity store) and `permguard.rego.data.v1` (a JSON document) — not names a caller invents. The
  `type` a request states is an assertion checked against the manifest's, never a selector: a
  caller cannot choose the parser for bytes it also supplies. `required: true` refuses a request
  that omits an input the partition's policies read, instead of deciding against an empty world.

- **Rego reads its input at `input.partition`**, not `data.entities`. `data` is the partition's own
  compiled world, identical for every request; grafting a caller's document into it made a global
  store that changed per evaluation — a shared surface nothing could validate.

- **The Helm chart's PodDisruptionBudget is one name and one number** (`budget: minAvailable`,
  `value: 1`) rather than two optional keys. A values file choosing one had to null the other out,
  and `helm template` honoured that null while `helm lint` did not: the same files rendered
  correctly and linted as a mistake nobody had made.

### Added

- **A decision has a deadline, and the engines are told about it.** The transport's request timeout
  ends the response; it does not end the work, which runs on a blocking thread that keeps going
  after the concurrency permit is released. Each decision now carries a budget — nine tenths of the
  transport's timeout — checked before a partition is evaluated and handed to Rego's interpreter as
  its execution limit. Rego's one-second budget bounded a single *rule*, so a partition with many
  modules could spend it many times over and still call itself bounded.

- **The evaluation queue is bounded.** Work is handed out through a fixed-depth channel; when it is
  full the submitting thread does the job itself. An unbounded queue was the wrong shape for a
  decision path — a request whose timeout has fired releases the permit that was limiting how many
  of these could be in flight, and with nothing bounding the queue that is how a plane under load
  accumulates work nobody is waiting for.

- **`extraVolumes` and `extraVolumeMounts` on every component of the chart.** The configuration
  names TLS certificates and authorities by path and the chart offered no way to put a file there:
  mutual TLS meant forking the chart or running a post-renderer.

- **`bench/decide.js`** measures the decision path — cold and warm, single and boxcarred — with
  thresholds on the warm path only. The rest of `bench/` measures the transport with nothing behind
  it, which was the whole suite until now.

- **A Rego partition can declare a schema.** `schema: true` plus one `.regoschema` file — JSON
  Schema, draft 2020-12, compiled once when the partition loads — and `input.partition` is checked
  against it before any rule runs. Rego is untyped by design and that is a virtue in a rule; it is
  not one in the data a rule reads, where a renamed field turns a guardrail into a rule that
  quietly never fires. Local only: a schema naming a remote `$ref` fails to compile rather than
  reaching for the network.

- **A profile's partitions are evaluated in parallel**, on a bounded process-wide pool, with the
  first job run by the calling thread — so a single-partition profile dispatches nothing and costs
  what it always did. Results come back in the manifest's order whatever order they finished in,
  and a partition that comes apart is a missing answer, which denies. The data plane runs the whole
  batch off the async runtime.

### Fixed

- **Tests no longer share fixed temporary directories.** Twelve suites named a directory after
  themselves, so two `cargo test` runs at once — or one after a run that left files behind —
  collided and failed for reasons unrelated to the code. Two full suites now run concurrently,
  green.

- **A plane id that names no plane is no longer read as the data plane.** Four places matched on a
  string and fell through to `data-plane`, so a typo produced a plausible document about the wrong
  process. `PlaneId` makes the wrong id unrepresentable.

- **The process registry is built from values, not string concatenation**, like the rest of the
  discovery documents.

- **A shared HTTP/gRPC port answers `404` for a path it does not serve.** The gRPC router's
  fallback took every unmatched path, so an HTTP client asking for a missing route was told
  `200 OK` with `grpc-status: 12` and an empty body. A gRPC caller still gets `UNIMPLEMENTED`; an
  HTTP caller now gets a `404` that says so. It matters most for discovery: a client probing for a
  document was being told "yes" by a port that serves nothing there.

- **gRPC and HTTP resolve a boxcarred batch the same way.** An evaluation stating
  `"partition_inputs": {}` replaces the request's defaults with nothing; one stating none inherits
  them. A proto3 `map` cannot tell an absent field from an empty one, so over gRPC `{}` was read as
  "unset" and *inherited* — the same request refused over HTTP and permitted over gRPC. The
  evaluation's field is a `PartitionInputs` message now, which has explicit presence; the old tag
  is reserved rather than reused, because a map and a message are different encodings.

- **The manifest refuses a key it does not know.** `deny_unknown_fields` on every YAML section, and
  the CBOR decoder — which documented itself as fail-closed and was not — rejects an unknown map
  key. `requred: true` was accepted and `required` stayed `false`: one transposed letter turning a
  partition whose data is mandatory into one where it is optional, silently, in the file whose
  whole job is to say what is mandatory. Forward compatibility is not lost, it is where the
  manifest already puts it: a ledger needing a newer reader says so in `runtimes.<key>.engine`, and
  the load gate refuses by name.

- **A profile must name at least one partition, and none of them twice**, and a manifest must
  declare at least one profile. A profile naming none can only ever deny, with nothing to cite; one
  naming a partition twice would ask it twice and cite it twice. Profile names now follow the same
  grammar as everything else the model names.

- **A boxcarred batch no longer copies its inputs once per evaluation.** With the default of 256
  evaluations, a one-megabyte entity store became hundreds of megabytes of identical copies before
  a policy had been consulted. Evaluations that inherit share one map; the resolved request is
  shared with the blocking evaluation rather than cloned into it.

- **gRPC no longer answers a request it did not fully receive.** The client hand-walked the JSON
  and dropped what it could not represent: a `context` that was not an object became no context,
  `evaluations: null` became no evaluations, an unknown `evaluations_semantic` became the default.
  It now reads the payload with the same `CheckRequest` the HTTP binding reads, then converts. The
  server refuses an enum value nobody defined instead of reading it as `execute_all`.

- **A schema file in a partition that declares none is refused**, not walked past. Skipping it was
  the worst of the three outcomes: the author sees the file, believes their inputs are validated,
  and nothing validates anything. The file extensions are asked of the language rather than
  hard-coded, so a second language with a schema is found.

## [0.1.2] - 2026-08-26

### Fixed

- **Tests no longer share fixed temporary directories.** Twelve suites named a directory after
  themselves, so two `cargo test` runs at once — or one after a run that left files behind —
  collided and failed for reasons unrelated to the code. Two full suites now run concurrently,
  green.

- **A plane id that names no plane is no longer read as the data plane.** Four places matched on a
  string and fell through to `data-plane`, so a typo produced a plausible document about the wrong
  process. `PlaneId` makes the wrong id unrepresentable.

- **The process registry is built from values, not string concatenation**, like the rest of the
  discovery documents.

- Container registries no longer expose Cosign's internal `sha256-*.sig` artifacts as broken image
  versions. Image provenance remains available through GitHub Artifact Attestations, while release
  checksums remain signed with Cosign.
- Homebrew publishes the current CLI as `permguard/tap/cli` and its versioned aliases as
  `cli@<version>` and `cli@<major>`, without leaking the implementation language into the cask name.

## [0.1.1] - 2026-08-26

### Fixed

- **Tests no longer share fixed temporary directories.** Twelve suites named a directory after
  themselves, so two `cargo test` runs at once — or one after a run that left files behind —
  collided and failed for reasons unrelated to the code. Two full suites now run concurrently,
  green.

- **A plane id that names no plane is no longer read as the data plane.** Four places matched on a
  string and fell through to `data-plane`, so a typo produced a plausible document about the wrong
  process. `PlaneId` makes the wrong id unrepresentable.

- **The process registry is built from values, not string concatenation**, like the rest of the
  discovery documents.

- Container images reach Docker Hub again, alongside GHCR. The release logged in to Docker Hub and
  then pushed nowhere near it: no `images:` entry ever named it. Versioned tags only — `latest` and
  `0.0` on those names still carry the Go implementation, and move when it does.
- The Helm chart's default images exist. `registry: ghcr.io` used to render
  `ghcr.io/permguard/control-plane`, a name that was never published; the registry value carries the
  namespace now, so `docker.io/permguard` and `ghcr.io/permguard/permguard` both resolve.

### Added

- **A decision has a deadline, and the engines are told about it.** The transport's request timeout
  ends the response; it does not end the work, which runs on a blocking thread that keeps going
  after the concurrency permit is released. Each decision now carries a budget — nine tenths of the
  transport's timeout — checked before a partition is evaluated and handed to Rego's interpreter as
  its execution limit. Rego's one-second budget bounded a single *rule*, so a partition with many
  modules could spend it many times over and still call itself bounded.

- **The evaluation queue is bounded.** Work is handed out through a fixed-depth channel; when it is
  full the submitting thread does the job itself. An unbounded queue was the wrong shape for a
  decision path — a request whose timeout has fired releases the permit that was limiting how many
  of these could be in flight, and with nothing bounding the queue that is how a plane under load
  accumulates work nobody is waiting for.

- **`extraVolumes` and `extraVolumeMounts` on every component of the chart.** The configuration
  names TLS certificates and authorities by path and the chart offered no way to put a file there:
  mutual TLS meant forking the chart or running a post-renderer.

- **`bench/decide.js`** measures the decision path — cold and warm, single and boxcarred — with
  thresholds on the warm path only. The rest of `bench/` measures the transport with nothing behind
  it, which was the whole suite until now.

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

- **A decision has a deadline, and the engines are told about it.** The transport's request timeout
  ends the response; it does not end the work, which runs on a blocking thread that keeps going
  after the concurrency permit is released. Each decision now carries a budget — nine tenths of the
  transport's timeout — checked before a partition is evaluated and handed to Rego's interpreter as
  its execution limit. Rego's one-second budget bounded a single *rule*, so a partition with many
  modules could spend it many times over and still call itself bounded.

- **The evaluation queue is bounded.** Work is handed out through a fixed-depth channel; when it is
  full the submitting thread does the job itself. An unbounded queue was the wrong shape for a
  decision path — a request whose timeout has fired releases the permit that was limiting how many
  of these could be in flight, and with nothing bounding the queue that is how a plane under load
  accumulates work nobody is waiting for.

- **`extraVolumes` and `extraVolumeMounts` on every component of the chart.** The configuration
  names TLS certificates and authorities by path and the chart offered no way to put a file there:
  mutual TLS meant forking the chart or running a post-renderer.

- **`bench/decide.js`** measures the decision path — cold and warm, single and boxcarred — with
  thresholds on the warm path only. The rest of `bench/` measures the transport with nothing behind
  it, which was the whole suite until now.

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
- **Authorization decisions** on the data plane: the `permguard.pdp.v1` interface — served
  identically over HTTP (`POST /access/v1/evaluation`, `/access/v1/evaluations`, and a discovery
  document) and gRPC
  (`permguard.data.v1.PolicyDecisionPoint`). `zone` and `ledger` are **required fields of the
  payload**, by name or by identity: one endpoint answers for every ledger a plane holds, and a
  request naming neither is refused with `400` rather than answered against a default. Boxcarring
  and the three `options.evaluations_semantic` values are implemented. Both built-in
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
