<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Permguard

[![ci](https://github.com/permguard/permguard/actions/workflows/ci.yml/badge.svg)](https://github.com/permguard/permguard/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)

Permguard is a Rust workspace for running policy authorization as a set of small,
auditable services.

It gives you:

- a **control plane** that stores zones, ledgers, policy objects and decision logs;
- a **data plane** that mirrors policy ledgers and answers authorization checks;
- an **all-in-one runtime** for local development and demos;
- a `permguard` CLI for authoring, pushing, pulling, checking and inspecting policies;
- built-in policy language support for **Cedar** and **Rego**;
- signed, content-addressed policy objects and verifiable decision records.

The local developer path is intentionally small: build the workspace, run the
all-in-one process, create a zone and ledger, push the sample policies, then ask
the data plane for a decision.

## Requirements

- Rust `1.97` or newer.
- `cargo`.
- Either `task` or `make`; both expose the same development commands.
- Docker Compose, only for the observability lab.
- `jq`, useful for JSON examples.
- `k6`, only for load tests.

## Quick Start

Build everything:

```sh
task build
# or
make build
```

Start the local all-in-one runtime:

```sh
task run:all
# or
make run-all
```

This starts both planes in one process:

```text
control plane  http://127.0.0.1:7556
data plane     http://127.0.0.1:7656
telemetry      http://127.0.0.1:7558
```

In another shell, inspect the runtime:

```sh
task cli -- inspect
# or
make cli ARGS="inspect"
```

Create a tenant boundary and a policy ledger:

```sh
task cli -- zones create acme --endpoint http://127.0.0.1:7556
task cli -- ledgers create main-ledger --zone acme --endpoint http://127.0.0.1:7556
```

Use the included PDP lab as a ready-made policy workspace:

```sh
task cli -- -w pdp-lab init pdp-lab --language cedar,rego
task cli -- -w pdp-lab remote add origin http://127.0.0.1:7556
task cli -- -w pdp-lab validate
task cli -- -w pdp-lab checkout origin/acme/main-ledger
task cli -- -w pdp-lab plan
task cli -- -w pdp-lab apply -m "lab policies"
```

Give the data plane one mirror interval, then ask for authorization decisions:

```sh
sleep 20
task cli -- -w pdp-lab check -f pdp-lab/requests/permit.json
task cli -- -w pdp-lab check -f pdp-lab/requests/deny.json
```

Read back the decisions recorded by the data plane and shipped to the control
plane:

```sh
task cli -- decisions list --zone acme --ledger main-ledger
task cli -- decisions tail --zone acme --ledger main-ledger --follow
```

## Common Commands

```sh
task cli -- --help                         # CLI help
task cli -- config show                    # show CLI configuration
task cli -- zones list                     # list zones
task cli -- ledgers list --zone acme       # list ledgers in a zone
task cli -- -w pdp-lab status              # local workspace state
task cli -- -w pdp-lab history             # tracked ledger history
task cli -- -w pdp-lab verify              # verify remote head and local closure
task cli -- -w pdp-lab objects list        # inspect the local object store
task cli -- completion zsh                 # shell completions
```

Direct Cargo invocations are useful when you do not want the task wrapper:

```sh
cargo run -p permguard-cli --bin permguard -- --help
cargo run -p permguard-all-in-one --bin permguard-all-in-one -- crates/permguard-all-in-one/config.local.yml
cargo run -p permguard-control-plane --bin permguard-control-plane -- crates/permguard-control-plane/config.local.yml
cargo run -p permguard-data-plane --bin permguard-data-plane -- crates/permguard-data-plane/config.local.yml
```

## Running Modes

Use the all-in-one runtime for local work:

```sh
task run:all
task run-as-tls:all
task run-as-mtls:all
```

Run the planes separately when you want the deployment shape:

```sh
task run:control
task run:data
```

The local configuration files live with the binaries:

```text
crates/permguard-all-in-one/config.local.yml
crates/permguard-control-plane/config.local.yml
crates/permguard-data-plane/config.local.yml
```

Each server command accepts the config path as its positional argument and can
override common settings from the command line:

```sh
cargo run -p permguard-control-plane --bin permguard-control-plane -- \
  crates/permguard-control-plane/config.local.yml \
  --public-http-addr 127.0.0.1:7556 \
  --log-level debug \
  --log-format terminal
```

## What The CLI Does

`permguard` is the operator and authoring tool. It can:

- create, list, update and delete zones;
- create, list, update and delete ledgers inside a zone;
- initialize a local policy workspace;
- add remotes, checkout ledgers, pull remote state and apply local changes;
- validate Cedar and Rego policy sources before upload;
- inspect local policy objects;
- ask a data plane for a decision with `permguard check`;
- read, tail, export and verify decision records;
- generate shell completions.

Examples:

```sh
task cli -- init my-policies --language cedar
task cli -- remote add origin http://127.0.0.1:7556
task cli -- checkout origin/acme/main-ledger
task cli -- refresh
task cli -- validate
task cli -- plan
task cli -- apply -m "update policies"
task cli -- check --subject User:alice --action read --resource Document:budget
```

## PDP Lab

`pdp-lab/` is the fastest way to see Permguard work end to end. It contains:

```text
pdp-lab/
|-- manifest.yml
|-- cedar/documents.cedar
|-- cedar/model.cedarschema
|-- rego/gateway.rego
`-- requests/*.json
```

The lab demonstrates one ledger with two partitions:

- `cedar`, with schema-backed document policies;
- `rego`, with a gateway policy;
- `default`, a profile that evaluates both partitions;
- `gateway`, a profile that evaluates only the Rego partition.

After applying the lab, these checks exercise the data plane:

```sh
task cli -- -w pdp-lab check -f pdp-lab/requests/permit.json
task cli -- -w pdp-lab check -f pdp-lab/requests/deny.json
task cli -- -w pdp-lab check -f pdp-lab/requests/gateway-permit.json
task cli -- -w pdp-lab check -f pdp-lab/requests/boxcarred.json -o json
```

You can also call the HTTP API directly:

```sh
curl -s http://127.0.0.1:7656/.well-known/authzen-configuration | jq
curl -s -X POST http://127.0.0.1:7656/access/v1/evaluation \
  -H 'content-type: application/json' \
  -H 'x-request-id: lab-1' \
  -d "$(jq '. + {zone: "acme", ledger: "main-ledger"}' pdp-lab/requests/permit.json)" | jq
```

## Observability Lab

Start the local Compose lab with both planes plus Prometheus, Grafana and Loki:

```sh
task lab:up
# or
make lab-up
```

Start only observability, useful when the planes are running on the host:

```sh
task lab:observability
```

Default local addresses:

```text
Grafana     http://127.0.0.1:7590
Prometheus  http://127.0.0.1:7591
Loki        http://127.0.0.1:7592
Control     http://127.0.0.1:7556
Data        http://127.0.0.1:7656
```

Stop the lab:

```sh
task lab:down
task lab:clean     # also removes lab volumes
```

## Load Testing

Run the control plane in release mode for benchmarks:

```sh
task bench:server
```

Then run one of the k6 profiles:

```sh
task bench:peak
task bench:ladder
task bench:shed
task bench:grpc
task bench:tls
task bench:hold
```

To send k6 client metrics to the lab Prometheus:

```sh
task lab:observability
task bench:grafana
```

The benchmark scripts are in `bench/`.

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

The structural checks are part of the normal check path:

```sh
task check:core-deps         # keep permguard-core dependency-light
task check:seams             # keep concrete construction in composition roots
task check:systems           # keep Taskfile and Makefile aligned
task check:headers           # license headers
```

Before opening a change, run:

```sh
task check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules and
[COMPATIBILITY.md](COMPATIBILITY.md) for compatibility promises.

## License

Apache-2.0. See [LICENSE](LICENSE).
