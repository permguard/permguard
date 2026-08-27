<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Permguard

<p align="center">
  <img src="assets/permguard-banner.png" alt="Permguard" width="820">
</p>

[![ci](https://github.com/permguard/permguard/actions/workflows/ci.yml/badge.svg)](https://github.com/permguard/permguard/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)

**Authorization policy, versioned like code and shipped like code.**

Permguard keeps your policies in a content-addressed, Git-like ledger, distributes signed
versions over a protocol built for it, and answers `can this subject do this to this?` —
either from its own data plane, or from **inside your process, at zero network cost**.

```text
       authors + CI                     ┌──────────────────┐
            │                           │  CONTROL  PLANE  │        the ledger
     permguard apply ────── NOTP ──────►│                  │   commits · trees · blobs
            │                           │  zones · ledgers │   signed heads · audit
            │                           └────────┬─────────┘
            │                                    │  NOTP: pull the objects,
            ▼                                    │  verify the signed head
    ┌───────────────┐                            │
    │   workspace   │                ┌───────────┴───────────┐
    │  manifest.yml │                ▼                       ▼
    │  cedar/ rego/ │       ┌─────────────────┐    ┌───────────────────────┐
    │  requests/    │       │   DATA  PLANE   │    │   YOUR  RUNTIME       │
    │  tests/       │       │  Permguard PDP  │    │  embed · sidecar      │
    └───────┬───────┘       │  HTTP · gRPC    │    │  same objects,        │
            │               └────────┬────────┘    │  same engines         │
    permguard test                   │             └───────────┬───────────┘
   (decide it offline,               └──────────┬──────────────┘
    no plane at all)                            │
                                       decisions + signed log
                                                │
                                                ▼
                                        back to the control plane,
                                        verifiable after the fact
```

## Why this is not another policy server

**Policy is a repository, not a blob.** `init`, `validate`, `plan`, `apply`, `pull`, `history` —
a workspace on disk, commits, trees and blobs, all content-addressed. A decision does not cite
"the policy that was live"; it cites the **exact commit** and the **identity of the policy** that
decided, and those identities survive a rename. You can check out the state a decision was made
against, months later, and re-ask the question.

**One question, many engines.** A ledger holds **partitions** — Cedar here, Rego there — and a
**profile** says which of them answer. `admin` consults the org chart *and* the guardrails;
`pipeline` consults the rules for machines and loads nothing else. An explicit deny from any
partition beats a permit from another, so "who is entitled" and "is it safe right now" can be
written by different people, in different languages, and still compose.

**Bring your own data plane.** The objects are self-describing and the engines are a library.
Run Permguard's data plane, or pull the ledger and evaluate **in your own process** — no PDP hop,
no network on the decision path, the same manifest, the same engines, the same answer.
`permguard test` is that path, in the CLI: it decides a workspace off disk, before anything is
pushed anywhere.

**NOTP, not "an API".** Policy distribution is content-addressed transfer with negotiation — send
what the other side is missing, and nothing else — over HTTP or gRPC, with a **signed head** at
the end of it. A data plane refuses a ledger whose head it cannot verify, and refuses one whose
engine range it is outside: an engine interpreting the same policies differently is a silent
authorization bypass, not a compatibility note.

**Decisions are evidence.** Every decision can be recorded with the commit, the policy identity,
the reason, and **keyed commitments** over what the caller supplied — proof of the inputs without
keeping them. The log is hash-chained, shipped to the control plane, and verifiable afterwards by
somebody who does not trust the plane that wrote it.

**Standard on the wire.** The decision API is the **OpenID AuthZEN** shape — `subject`, `action`,
`resource`, `context`, boxcarring, the metadata document — with the extensions stated plainly and
the differences written down, in [`crates/permguard-languages/src/request.rs`](crates/permguard-languages/src/request.rs).
No badge, no surprises.

## Install

```sh
brew install permguard/tap/cli
permguard --help
```

<details>
<summary>From this checkout instead</summary>

```sh
cargo install --path crates/permguard-cli --bin permguard --force
export PATH="$HOME/.cargo/bin:$PATH"
```

Needs Rust `1.97`+, `cargo`, and `task` or `make`. Docker Compose for the observability lab,
`jq` for the JSON examples, `k6` only for load testing.

</details>

## Five minutes

### 1. A workspace is a directory

`examples/basics/manifest.yml` — what this ledger is, what it holds, and how it may be asked:

```yaml
runtimes:
  cedar:
    language: { name: cedar, constraint: ">=4.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }
  rego:
    language: { name: rego, constraint: ">=1.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }

partitions:
  cedar:
    runtime: cedar
    schema: true                                     # and every policy type-checks against it
    input: { type: permguard.cedar.entities.v1, required: false }   # what a request may hand it
  rego:
    runtime: rego
    schema: false

profiles:
  default: { type: permguard.pdp.v1, partitions: [cedar, rego] }   # both answer
  gateway: { type: permguard.pdp.v1, partitions: [rego] }          # only the machine rules
```

Beside it, the policies. Cedar:

```cedar
@alias("document-readers")
permit (
    principal in Group::"finance",
    action == Action::"read",
    resource
);

@alias("document-owners")
permit (
    principal,
    action == Action::"write",
    resource
) when { resource.owner == principal };
```

`@alias` is a handle for people. What a decision cites is the **identity** Permguard derives and
keeps across renames — so the audit trail still names the same policy after somebody tidies the
file.

And Rego, in the same ledger, answering under its own profile:

```rego
# METADATA
# custom:
#   alias: gateway-access
package gateway.access

import rego.v1

default allow := false

allow if {
    input.subject.properties.role == "admin"
    input.action.name in {"create", "update", "delete"}
}
```

### 2. Ask it, with no server anywhere

```sh
permguard -w examples/basics validate    # parses, type-checks against the schema, derives identities
permguard -w examples/basics test        # and does it decide what you meant?
```

```text
  ok    a member of the finance group may read a document      [default] permit by document-readers, gateway-access
  ok    writing a document somebody else owns is refused       [default] deny, nothing permitted it
  ok    the gateway profile answers with Rego alone            [gateway] permit by gateway-access

  asked these sources, compiled here

5 case(s), 5 passed, 0 failed.
```

Same engines a data plane uses, same routing, same resolution — compiled from the working tree.
This is the "bring your own data plane" path, and it is also your test suite.

<details>
<summary>Run it through the Taskfile instead</summary>

```sh
task cli -- -w examples/basics validate
task cli -- -w examples/basics test
```

</details>

### 3. Now publish it and ask a real PDP

```sh
task run:all                             # control plane :7556, data plane :7656, telemetry :7558

permguard zones create acme
permguard ledgers create main-ledger --zone acme

permguard -w examples/basics init basics --language cedar,rego   # the example ships the sources; this tracks them
permguard -w examples/basics remote add origin http://127.0.0.1:7556
permguard -w examples/basics checkout origin/acme/main-ledger
permguard -w examples/basics plan
permguard -w examples/basics apply -m "lab policies"
```

The data plane mirrors it, verifies the signed head, compiles each partition once, and serves:

```sh
permguard -w examples/basics check -f requests/permit.json
permguard -w examples/basics --data-endpoint grpc://127.0.0.1:7656 check -f requests/permit.json
permguard -w examples/basics test --remote   # the same cases, against the plane
```

Straight at the API, which is AuthZEN:

```sh
curl -s http://127.0.0.1:7656/.well-known/authzen-configuration | jq

curl -s -X POST http://127.0.0.1:7656/access/v1/evaluation \
  -H 'content-type: application/json' -H 'x-request-id: lab-1' \
  -d "$(jq '. + {zone: "acme", ledger: "main-ledger"}' examples/basics/requests/permit.json)" | jq
```

<details>
<summary>Run it through the Taskfile instead</summary>

```sh
task run:all

task cli -- zones create acme
task cli -- ledgers create main-ledger --zone acme

task cli -- -w examples/basics init basics --language cedar,rego
task cli -- -w examples/basics remote add origin http://127.0.0.1:7556
task cli -- -w examples/basics checkout origin/acme/main-ledger
task cli -- -w examples/basics apply -m "lab policies"
task cli -- -w examples/basics check -f requests/permit.json
```

</details>

### 4. What a request looks like

```json
{
  "subject":  { "type": "User", "id": "alice" },
  "action":   { "name": "read", "properties": { "risk": "high" } },
  "resource": { "type": "Document", "id": "budget-2026" },
  "context":  { "environment": "production" },

  "partition_inputs": {
    "cedar": {
      "type": "permguard.cedar.entities.v1",
      "data": [ { "uid": { "type": "Group", "id": "finance" } } ]
    }
  }
}
```

`subject`, `action`, `resource` and `context` reach **every** partition of the profile.
`partition_inputs` reaches **one**, by the partition's own name — because an entity store is
written in Cedar's shape, a Rego document in JSON, and two Cedar partitions with different schemas
hold different worlds. The **ledger** decides what each partition accepts; the `type` in the
request is checked against that and never obeyed, so a caller can never pick the parser for bytes
it also supplies.

An action's properties reach Rego at `input.action.properties`. Cedar cannot carry attributes on an
action at all, so Permguard projects them into `context.action` — and refuses a caller who writes
that key. One request, two readings, nothing for a caller to keep in step.

### 5. Read the decisions back, and verify them

```sh
permguard decisions list --zone acme --ledger main-ledger
permguard decisions tail --zone acme --ledger main-ledger --follow
permguard decisions get  <decision-id> --zone acme --ledger main-ledger

# and check the chain and the signatures, with the plane's published keys
permguard decisions list --zone acme --ledger main-ledger --verify --keys data-plane-keys.json
```

The `decision id` a caller gets back is the one the record carries: an answer and its evidence are
joined by an identifier, not by a timestamp and a guess.

## Examples

| Example | Domain | What it shows |
| --- | --- | --- |
| [`examples/basics`](examples/basics) | users, groups, documents | the platform end to end — apply, mirror, decide, read the decisions back, verify them, and two workspaces pushing at each other |
| [`examples/release-pipeline`](examples/release-pipeline) | software delivery | a realistic set of controls — team ownership, machine identities, separation of duties, incident-only rollback — and the evidence they leave |

The reasoning behind the second, written for somebody who has never used Permguard, is in
[`docs/use-cases/release-pipeline.md`](docs/use-cases/release-pipeline.md).

Copy one into a scratch directory and take it apart:

```sh
mkdir -p playground/basics && cd playground/basics
task cp-basics          # or: task cp-rspipe
```

## Run Commands

Use `task`:

```sh
task build                         # build the workspace
task run:all                       # control + data plane in one process
task run:control                   # control plane only
task run:data                      # data plane only
task run-as-tls:all                # all-in-one with TLS
task run-as-mtls:all               # all-in-one with HTTP TLS and gRPC mTLS
```

Use `make`:

```sh
make build
make run-all
make run-control
make run-data
make run-as-tls-all
make run-as-mtls-all
```

Use the installed CLI:

```sh
permguard --help                   # CLI help
permguard inspect                  # inspect local planes
permguard config show              # show CLI configuration
permguard completion zsh           # shell completions
```

Use Cargo directly for runtime binaries:

```sh
cargo run -p permguard-all-in-one --bin permguard-all-in-one -- crates/permguard-all-in-one/config.local.yml
cargo run -p permguard-control-plane --bin permguard-control-plane -- crates/permguard-control-plane/config.local.yml
cargo run -p permguard-data-plane --bin permguard-data-plane -- crates/permguard-data-plane/config.local.yml
```

Server commands accept a config file and optional overrides:

```sh
cargo run -p permguard-control-plane --bin permguard-control-plane -- \
  crates/permguard-control-plane/config.local.yml \
  --public-http-addr 127.0.0.1:7556 \
  --public-grpc-addr 127.0.0.1:7556 \
  --telemetry-addr 127.0.0.1:7558 \
  --log-level debug \
  --log-format terminal
```

Local configs:

```text
crates/permguard-all-in-one/config.local.yml
crates/permguard-all-in-one/config.local-tls.yml
crates/permguard-all-in-one/config.local-mtls.yml
crates/permguard-control-plane/config.local.yml
crates/permguard-control-plane/config.local-tls.yml
crates/permguard-control-plane/config.local-mtls.yml
crates/permguard-data-plane/config.local.yml
crates/permguard-data-plane/config.local-tls.yml
crates/permguard-data-plane/config.local-mtls.yml
```

## CLI Workflow

Create and manage remote state:

```sh
permguard zones create acme --endpoint http://127.0.0.1:7556
permguard zones list
permguard zones get acme
permguard ledgers create --zone acme main-ledger
permguard ledgers list --zone acme
permguard ledgers get --zone acme main-ledger
```

Author and publish policies:

```sh
mkdir my-policies
permguard -w my-policies init my-policies --language cedar
permguard -w my-policies remote add origin http://127.0.0.1:7556
permguard -w my-policies checkout origin/acme/main-ledger
permguard -w my-policies refresh
permguard -w my-policies validate
permguard -w my-policies plan
permguard -w my-policies apply -m "update policies"
permguard -w my-policies status
permguard -w my-policies history
permguard -w my-policies verify
```

Inspect local objects:

```sh
permguard -w my-policies objects list
permguard -w my-policies objects list --tracked
permguard -w my-policies objects prune --dry-run
permguard -w my-policies objects cat <digest> --human
```

Ask for authorization:

```sh
permguard -w my-policies check --subject User:alice --action read --resource Document:budget
permguard -w my-policies check -f request.json
cat request.json | permguard -w my-policies check -f -
permguard check -f request.json --zone acme --ledger main-ledger -o json
```

Read and verify decision records:

```sh
permguard decisions list --zone acme --ledger main-ledger
permguard decisions tail --zone acme --ledger main-ledger --follow
permguard decisions get <decision-id> --zone acme --ledger main-ledger
permguard decisions export --zone acme --ledger main-ledger -o json
permguard decisions list --zone acme --ledger main-ledger --verify --keys data-plane-keys.json
```

## Inside an example

```text
examples/release-pipeline/
|-- manifest.yml            three partitions, two pdp profiles, one input contract each
|-- admin-cedar/            the org chart — teams, ownership, roles (schema, type-checked)
|   `-- model.cedarschema
|-- admin-rego/             the guardrails — deny only, and a JSON Schema over their own input
|   `-- guardrails.regoschema
|-- pipeline-rego/          what CI, the signer and the controller may do
|-- requests/*.json         twenty-three decision requests, refusals included
`-- tests/release.yml       what this workspace claims its own policies decide
```

Two of the three partitions run Rego. A profile compiles the partitions it names and nothing else,
so `pipeline` never loads the guardrails and `admin` never loads the rules for machines. Each
partition declares what a request may hand it — the org chart is **required**, the guardrails' list
is optional, and the pipeline rules accept nothing — and the suite asserts every way a caller can
get that wrong.

Each example has its own README with the commands and the decisions they produce. `lab/` at the
repository root is something else: the configuration of the observability stack below.

## Observability Lab

Start both planes plus Prometheus, Grafana and Loki:

```sh
task lab:up
# or
make lab-up
```

Start only observability for planes running on the host:

```sh
task lab:observability
# or
make lab-observability
```

Print the local addresses:

```sh
task lab:where
# or
make lab-where
```

Defaults:

```text
Grafana     http://127.0.0.1:7590
Prometheus  http://127.0.0.1:7591
Loki        http://127.0.0.1:7592
Control     http://127.0.0.1:7556
Data        http://127.0.0.1:7656
```

Follow logs and stop the lab:

```sh
task lab:logs
task lab:logs SERVICE=grafana
task lab:down
task lab:clean
```

## Load Testing

Start the benchmark server:

```sh
task bench:server
```

Run k6 profiles:

```sh
task bench:peak
task bench:ladder
task bench:shed
task bench:grpc
task bench:tls
task bench:hold
```

Send k6 metrics to the observability lab:

```sh
task lab:observability
task bench:grafana
```

## Workspace Layout

| Crate | Purpose |
| --- | --- |
| `permguard-core` | Shared contracts: storage, secrets, signing keys, audit, services and server host types. |
| `permguard-std` | Default implementations behind feature flags. |
| `permguard-transport` | HTTP, gRPC, TLS, mutual TLS, revocation, reload and graceful shutdown. |
| `permguard-telemetry` | Liveness, readiness and metrics. |
| `permguard-server` | Server host, service registry, command dispatch and plane composition support. |
| `permguard-languages` | Built-in Cedar and Rego integration. |
| `permguard-objects` | Canonical policy objects, digests, manifests and signed head statements. |
| `permguard-notp` | Negotiated Object Transfer Protocol messages and codecs. |
| `permguard-control-client` | Client-side access to endpoints, trust material, catalogs, NOTP, decisions and mirrors. |
| `permguard-control-plane` | Control-plane binary, policy object storage, inventory and decision-log ingestion. |
| `permguard-data-plane` | Data-plane binary, mirror loop, authorization endpoint and decision recording. |
| `permguard-all-in-one` | Local runtime that runs control and data planes in one process. |
| `permguard-cli` | `permguard`, the command-line interface and authoring engine. |

## Development

```sh
task check                   # lint, structural checks and tests
task test                    # workspace tests
task test PKG=permguard-cli  # one crate
task lint                    # clippy with warnings denied
task coverage                # coverage gate
```

Structural checks:

```sh
task check:core-deps
task check:seams
task check:systems
task check:headers
```

Equivalent Make targets are available:

```sh
make check
make test
make lint
make coverage
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules and
[COMPATIBILITY.md](COMPATIBILITY.md) for compatibility promises.

## Documentation

| Area | Guide |
| --- | --- |
| Operations | [Verify released container images](docs/operations/container-verification.md) |

## License

Apache-2.0. See [LICENSE](LICENSE).
