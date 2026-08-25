<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Permguard

[![ci](https://github.com/permguard/permguard/actions/workflows/ci.yml/badge.svg)](https://github.com/permguard/permguard/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)

**Permguard is trustworthy authorization infrastructure for AI agents and
regulated systems.**

It implements a **Policy Decision Point (PDP)**: applications, agents and
services send authorization questions such as "can this subject perform this
action on this resource?", and Permguard answers with a decision that can be
recorded, audited and tied back to the exact policy version that produced it.

Permguard is built for environments where authorization must be explainable:

- AI agents that need external, policy-governed permission checks before acting;
- regulated systems that need repeatable decisions and audit evidence;
- multi-tenant platforms that separate policy authoring from runtime evaluation;
- teams that want Cedar and Rego policies in the same authorization workflow.

## What It Does

Permguard separates policy distribution from policy evaluation:

```text
policy authors + CI
        |
        v
permguard CLI  --apply-->  control plane  --mirror-->  data plane / PDP
                                |                         |
                                |                         v
                                |                  authorization decision
                                |                         |
                                v                         v
                         policy objects            signed decision log
```

- The **control plane** stores zones, ledgers, policy objects and decision logs.
- The **data plane** mirrors policy ledgers and serves the PDP decision endpoint.
- The **CLI** initializes workspaces, validates policies, pushes versions, checks
  decisions and reads/verifies decision records.
- The **object model** is content-addressed, so a decision can name the exact
  policy state that was evaluated.
- The **decision log** is designed for audit: records are produced by the data
  plane, shipped to the control plane and can be verified later.

## Multi-Language Policies

A Permguard policy workspace is described by a manifest. One ledger can contain
multiple language partitions and expose one or more PDP profiles.

Example from `pdp-lab/manifest.yml`:

```yaml
metadata:
  kind: policy
  name: pdp-lab
  description: The Permguard PDP laboratory - Cedar and Rego side by side.
  author: Nitro Agility S.r.l.
  license: Apache-2.0
runtimes:
  cedar:
    language: { name: cedar, constraint: ">=4.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }
  rego:
    language: { name: rego, constraint: ">=1.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }
partitions:
  cedar: { runtime: cedar, schema: true }
  rego:  { runtime: rego, schema: false }
profiles:
  default: { type: permguard.pdp.v1, partitions: [cedar, rego] }
  gateway: { type: permguard.pdp.v1, partitions: [rego] }
```

Cedar policy example:

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

Rego policy example:

```rego
# METADATA
# custom:
#   alias: gateway-access
package gateway.access

import rego.v1

default allow := false

allow if {
    input.subject.type == "User"
    input.action.name == "read"
}

allow if {
    input.subject.properties.role == "admin"
    input.action.name in {"create", "update", "delete"}
}
```

Decision request example:

```json
{
  "subject": { "type": "User", "id": "alice" },
  "action": { "name": "read" },
  "resource": { "type": "Document", "id": "budget-2026" },
  "context": { "time": "2026-08-24T10:00:00Z" }
}
```

## Requirements

- Rust `1.97` or newer.
- `cargo`.
- `task` or `make`.
- Docker Compose, for the lab and observability stack.
- `jq`, for JSON examples.
- `k6`, only for load testing.

## Install The CLI

Install the `permguard` command from this checkout:

```sh
cargo install --path crates/permguard-cli --bin permguard
```

Make sure Cargo's binary directory is on your `PATH`:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
permguard --help
```

During development, reinstall after CLI changes:

```sh
cargo install --path crates/permguard-cli --bin permguard --force
```

## Quick Start

Build everything:

```sh
task build
# or
make build
```

Start the all-in-one runtime:

```sh
task run:all
# or
make run-all
```

The local runtime exposes:

```text
control plane  http://127.0.0.1:7556
data plane     http://127.0.0.1:7656
telemetry      http://127.0.0.1:7558
```

Inspect the planes:

```sh
permguard inspect
```

Create a zone and a ledger:

```sh
permguard zones create acme --endpoint http://127.0.0.1:7556
permguard ledgers create main-ledger --zone acme --endpoint http://127.0.0.1:7556
```

Initialize and publish the included PDP lab:

```sh
permguard -w pdp-lab init pdp-lab --language cedar,rego
permguard -w pdp-lab remote add origin http://127.0.0.1:7556
permguard -w pdp-lab validate
permguard -w pdp-lab checkout origin/acme/main-ledger
permguard -w pdp-lab plan
permguard -w pdp-lab apply -m "lab policies"
```

Wait for the data plane to mirror the ledger, then ask for decisions:

```sh
sleep 20
permguard -w pdp-lab check -f pdp-lab/requests/permit.json
permguard -w pdp-lab check -f pdp-lab/requests/deny.json
permguard -w pdp-lab check -f pdp-lab/requests/gateway-permit.json
permguard -w pdp-lab check -f pdp-lab/requests/boxcarred.json -o json
```

Read the decision log:

```sh
permguard decisions list --zone acme --ledger main-ledger
permguard decisions tail --zone acme --ledger main-ledger --follow
permguard decisions export --zone acme --ledger main-ledger -o json
```

Call the PDP HTTP API directly:

```sh
curl -s http://127.0.0.1:7656/.well-known/authzen-configuration | jq

curl -s -X POST http://127.0.0.1:7656/access/v1/evaluation \
  -H 'content-type: application/json' \
  -H 'x-request-id: lab-1' \
  -d "$(jq '. + {zone: "acme", ledger: "main-ledger"}' pdp-lab/requests/permit.json)" | jq
```

Use gRPC instead of HTTP:

```sh
permguard -w pdp-lab --data-endpoint grpc://127.0.0.1:7656 check -f pdp-lab/requests/permit.json
permguard --control-endpoint grpc://127.0.0.1:7556 decisions list --zone acme --ledger main-ledger
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

## PDP Lab

`pdp-lab/` is a complete example policy workspace:

```text
pdp-lab/
|-- manifest.yml
|-- cedar/documents.cedar
|-- cedar/model.cedarschema
|-- rego/gateway.rego
`-- requests/*.json
```

Run it end to end:

```sh
task run:all

permguard zones create acme --endpoint http://127.0.0.1:7556
permguard ledgers create main-ledger --zone acme --endpoint http://127.0.0.1:7556

permguard -w pdp-lab init pdp-lab --language cedar,rego
permguard -w pdp-lab remote add origin http://127.0.0.1:7556
permguard -w pdp-lab validate
permguard -w pdp-lab checkout origin/acme/main-ledger
permguard -w pdp-lab plan
permguard -w pdp-lab apply -m "lab policies"

sleep 20

permguard -w pdp-lab check -f pdp-lab/requests/permit.json
permguard -w pdp-lab check -f pdp-lab/requests/deny.json
permguard -w pdp-lab check -f pdp-lab/requests/gateway-permit.json
permguard decisions list --zone acme --ledger main-ledger
```

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

## License

Apache-2.0. See [LICENSE](LICENSE).
