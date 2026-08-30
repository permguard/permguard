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

## [0.1.6] - 2026-08-30

### Added

- **A second decision interface: `permguard.api.pdp.temporal.v1alpha1`.** The one Permguard has
  always served answers *may this subject do this to this?* from the request. This one answers *may
  this happen, given what has happened?* — from the request **and** a durable history. An occurrence
  is submitted to `POST /temporal/v1alpha1/events` (or `TemporalPolicyDecisionPoint.SubmitEvent`),
  made durable, observed, and then decided; a history-only kind returns a receipt with **no
  `decision` field at all**, because a fabricated verdict a caller cannot tell from a decided one is
  the most dangerous thing such an interface could return. Off unless a deployment enables it.

- **Dogwood as a policy runtime**, through Amazon's `amzn-dogwood-language` at a reviewed immutable
  revision. Cedar plus history: a policy may ask what has happened recently as well as what is being
  asked now. Permguard supplies what a production deployment needs around it — the durable journal,
  provenance, replication, limits, and the failure modes upstream's reference interpreter documents
  as out of scope.

- **`permguard events list|tail|get|export|verify`**, reading from the control plane's event store.
  `export` fixes a snapshot from its first page and terminates on a ledger that is still recording;
  `verify` checks each record against its inclusion path and, with `--keys`, the signature over the
  batch — and says which of the two it did.

- **Bounded temporal evaluation.** Deciding against a history no longer means reading one: the
  journal keeps a rebuildable index beside its segments, and a decision range-scans it for one
  history partition over one time window. Each history partition has its own engine, kept in a
  bounded least-recently-used set; eviction costs a replay from the durable record and never an
  answer. `max_window` is a ceiling, not a reason to read everything under it.

- **`/.well-known/permguard-events-native-v1alpha1-configuration`**, and
  `EventLog.GetEventConfiguration` beside it: where batches go, which event types are accepted, and
  how read offsets are spelled — so a producer is configured with one URL rather than a runbook.

- **`config.local-experimental.yml` beside each server crate**, with `task run:experimental`,
  `make run-experimental` and `task cp-dogwood`: a working deployment with every experimental
  runtime this build carries turned on — today that is Dogwood and the event path it needs.

- **`experimental.<name>.enabled`**, one key per provisional runtime rather than a flag per
  language. A language declares itself experimental and the gate iterates, so a runtime added or
  graduated needs no change to the configuration types, the file schema or the composition roots.
  Naming a runtime this build does not gate is refused at startup instead of doing nothing.

- **`bench/temporal.js`**, measuring what an occurrence costs — recorded, decided, and under overlap.

- **A control-plane event store**: signed batch ingest, tenant-isolated reads, a bounded per-type
  index so listing one event type does not scan the rest, and retention that removes whole sealed
  segments while keeping the envelopes and archived keys that prove what stays.

### Changed - breaking, pre-release

- **Ports now identify server roles independently of transport security.** Server Host operations
  use `5443`, the Control Plane uses `6443`, the Data Plane uses `7443`, and `8443` is assigned to
  the Trust Plane. HTTP and HTTPS use the same role port; the scheme selects transport security.
  Every shipped configuration, client default, container, Helm workload, example, and discovery
  document now follows this convention. Standalone Server Hosts sharing a machine need distinct IP
  addresses or network namespaces rather than a different role port. The shipped mTLS profiles now
  multiplex HTTP and gRPC on the role port with one mutual-TLS policy, so both transports require a
  trusted client certificate instead of silently creating `7557/7657` side ports.

- **`permguard.pdp.v1` is now `permguard.api.pdp.native.v1`.** The old name says which product the
  interface belongs to; the new one says which of the two interfaces it *is*. A manifest that still
  writes the old name loads and is served identically — there is one contract and one legacy
  spelling of its name — but nothing generates it any more: the CLI writes the new name, the
  discovery documents advertise it, and the shipped examples carry it.

- **Read offsets are signed.** A decision-log offset used to be base64 JSON a consumer could edit:
  it could move itself to a position it was never given, present an offset issued for one tenant
  under another, or widen a filter after the fact. The API family, the scope, the normalized filters
  and the export bound are now inside a MAC, and presenting an offset under any of them changed is a
  stable refusal rather than a reinterpretation. **Outstanding offsets are invalidated by this
  change**; consumers resume from `oldest_available` or from the beginning.

- **Reads are bounded by bytes as well as records,** and report `oldest_available`,
  `high_watermark` and `coverage`. A record count alone does not bound a response. `permguard
  decisions export` now fixes a snapshot and terminates instead of chasing a moving end.

- **The event interfaces take two switches.** `dataPlane.events.enabled` and
  `controlPlane.events.enabled` now also require `experimental.dogwood.enabled`: one is a statement
  about disks, the other about accepting a contract whose shape is not yet stable. A plane that has
  said one and not the other refuses to start rather than serving an interface nobody can reach.

- **A temporal partition declares its history scope.** A schema with no universal symmetric pin
  ranges over the whole retained ledger on every evaluation, and that is now accepted out loud —
  `history: { scope: global }` — or refused. Declaring it on a partition that *is* pinned, or on a
  runtime that keeps no history, is refused too.

- **A partition declares typed artifacts.** `schema: true` remains valid for Cedar and Rego and
  means what it always did; a runtime that needs several distinct artifacts — Dogwood needs an
  action schema, and may need an event schema, macros and provider programs — declares them by
  registered name under `artifacts:`. The authoring walk and the plane's loader both ask the
  registry, so neither carries a switch that mentions a language.

### Fixed

- **A Rego partition attributed a decision to every policy sharing a package.** Two policies in one
  package produced a decision citing both, so an audit trail said a rule had decided when it had
  not. Two policies claiming one package are now refused at load, by name: a package is a namespace,
  and two files claiming it are two authors who each believe they own it.

- **The stateless request now refuses a field it does not know.** A misspelt member used to parse
  and be dropped — `"contxt"` beside `"subject"` produced a decision made *without* the context the
  caller believed it had sent, and the answer looked exactly like a correct one. Every level of the
  request is strict now; responses stay lenient, because that direction really is the reader's duty.

- **A gRPC number that is not a number is refused rather than becoming `null`.** `NaN`, infinity and
  a value with no `kind` all converted to JSON `null`, which is a *value a policy can test* — so a
  malformed request quietly became a well-formed one saying something else. The numeric domain is
  now stated and enforced, and `null` is spelled `NullValue`.

- **The gRPC client sent every request as a batch.** A single evaluation went over `EvaluateMany`,
  so the boxcarring semantics applied to a request that had not asked for them. It now picks by
  whether `evaluations` is non-empty.

- **A thread that failed to start was counted as one that ran.** The parallel evaluator ignored
  spawn failures, so a partition could be silently skipped and its `forbid` never seen. Started
  workers are counted, a shortfall is reported, and a fan-out with no workers runs locally.

- **A restarted plane could not reopen its own event journal.** The stream identity was compared
  including the producer *instance*, which is minted per process — so every restart was refused as
  somebody else's stream. The comparison is now over what identifies the chain; the instance is
  adopted from the recovered state, which is what continuing a chain means.

- **A restarted plane decided against an empty history.** The journal is durable and the engine that
  reads it starts empty, so every decision after a restart — or after a cache eviction — ranged over
  nothing, returning a `deny` indistinguishable from a correct one. A cold history is now replayed
  from the durable record before it decides.

- **A shared-mode rebuild discarded the plane's own history.** Absorbing imported events replayed
  only the imported half, silently dropping everything the plane had recorded itself. Local and
  imported records are now merged into one ordered run.

- **Two requests arriving on a cold ledger compiled it twice.** Reading a manifest and compiling a
  policy set are idempotent and expensive; without a gate, every request arriving while the first
  was compiling repeated the work and threw it away — a stampede at every restart, commit change and
  cache eviction. One caller now does the work and the rest wait for it, per key.

- **Loading a ledger blocked an async worker thread.** Reading, decoding and compiling now happen on
  a blocking thread, and the decision budget is measured from the start of the whole decision rather
  than from after the load it was meant to bound.

- **A commented example in a shipped configuration could not be used.** The `events` blocks sat
  under `log:`, so uncommenting them produced a file the plane refuses. Every example now lives
  under the section whose settings it shows, and a test uncomments each one and starts it.

- **`events.stream.group_commit_max_delay` did nothing.** It was read and never used: every
  submission paid for its own `fsync`. Overlapping submissions now share one.

- **`schema: false` declared nothing, and now does.** A partition with the flag off was treated as
  declaring an *optional* schema rather than none, so a schema file sitting beside it was accepted
  in silence — by the CLI at authoring and by the plane at load. Both now refuse it, which is what
  the flag has always meant.

## [0.1.5] - 2026-08-28

### Changed — breaking, pre-release

- **A plane publishes where it is reached, not where it binds.** `public.http.advertised_url` is
  the address the discovery documents name; absent, the bind address is used as before. This was a
  real defect on Kubernetes: a pod binds `0.0.0.0` because it has to, and every document this
  deployment served named `http://0.0.0.0:7443` — an address a listener understands and nothing can
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

[Unreleased]: https://github.com/permguard/permguard/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/permguard/permguard/releases/tag/v0.1.5
[0.1.2]: https://github.com/permguard/permguard/releases/tag/v0.1.2
[0.1.1]: https://github.com/permguard/permguard/releases/tag/v0.1.1
[0.1.0]: https://github.com/permguard/permguard/releases/tag/v0.1.0
