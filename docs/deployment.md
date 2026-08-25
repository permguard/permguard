<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deployment

The four legal shapes, and every port each binary answers on.

## Shapes

| Shape | Binaries | Legal |
| --- | --- | --- |
| Both planes, split | `permguard-control-plane` + `permguard-data-plane` | ✔ |
| Control plane alone | `permguard-control-plane` | ✔ |
| Data plane alone | `permguard-data-plane` | ✔ |
| All-in-one alone | `permguard-all-in-one` | ✔ |
| All-in-one beside a split plane | — | ✘ refused (Helm) / port collision (compose) |

## Ports

Default addresses; every one is configuration
(`controlPlane.public`, `dataPlane.public`, `telemetry.addr`).

| Port | Surface | control-plane | data-plane | all-in-one | Exposure |
| --- | --- | --- | --- | --- | --- |
| `7556` | Control plane — HTTP + gRPC | ✔ | — | ✔ | Public |
| `7656` | Data plane — HTTP + gRPC | — | ✔ | ✔ | Public |
| `7558` | Telemetry | ✔ | — | ✔ | **Cluster-internal only** |
| `7658` | Telemetry | — | ✔ | — | **Cluster-internal only** |

The all-in-one runs one process, so it has one telemetry surface (`7558`)
for both planes.

## What each surface answers

| Surface | Endpoints |
| --- | --- |
| Data plane, decisions (`7656`) | `POST /access/v1/evaluation` · `POST /access/v1/evaluations` · `GET /.well-known/authzen-configuration` · gRPC `permguard.data.v1.PolicyDecisionPoint` — the `permguard.pdp.v1` profile ([Answering decisions](authorization-check.md)) |
| Plane, public (`7556` / `7656`) | The plane's APIs · `/` `/health` `/version` · `/.well-known/server-configuration` (**this plane only** — OIDC-style: `jwks_uri`, and on the control plane the `notp_*_endpoint` URI templates) · `/<plane>/keys` (its JWKS) |
| Telemetry (`7558` / `7658`) | `/healthz` `/readyz` `/metrics` · `/.well-known/server-configuration` (**the process registry**: each hosted plane pointing at its own configuration document — pointers, never copies) |

## Discovery, by design

- A plane's public port describes **itself and nothing else**: exposing only
  the data plane reveals nothing about the control plane — not even that it
  exists, or on which port.
- The cross-plane **registry** is operator material and lives on the
  operator's port — the telemetry surface, which never leaves the cluster.
- The rule is uniform, no special cases: standalone, the registry lists one
  plane; all-in-one, two. Same code, same semantics.

```text
7556  control-plane (public)    APIs + self-description + /control-plane/keys
7656  data-plane    (public)    APIs + decisions (/access/v1/…) + self-description + /data-plane/keys
7558  telemetry     (internal)  probes + metrics + the process registry
```

## Signing rings on disk

Each plane signs what it answers with its own ring, on the volume, separate
from the operations ring that seals the audit trail:

| Ring | Directory | Signs | Published at |
| --- | --- | --- | --- |
| Operations | `keys/operations` | the audit trail seal | — (internal) |
| Control plane | `keys/control` | NOTP head statements | `/control-plane/keys` |
| Data plane | `keys/data` | decision responses (upcoming) | `/data-plane/keys` |

All three follow one lifecycle policy (`operations.keys`: publish-ahead,
rotation, retention), maintained by the same key service.

## Observability

Three signals, three postures — none may ever gate availability:

| Signal | How it leaves | When the destination is down |
| --- | --- | --- |
| Logs | stdout, JSON records | the runtime's problem, not the process's |
| Metrics | Prometheus exposition on the telemetry port | pull-based: nothing is lost server-side, the scraper just misses samples |
| Traces | OTLP/gRPC, only when `telemetry.otel.enabled` is on | batch export from a dedicated thread with a bounded queue: **spans drop, requests never slow down or fail** |

```yaml
telemetry:
  otel:
    enabled: "true"
    endpoint: "http://tempo:4317"   # any OTLP/gRPC collector
    sample_rate: "1.0"              # 0.0..=1.0
```

The compose lab ships the full stack — Prometheus, Loki, **Tempo**, Grafana
with the datasources and dashboards provisioned (`Permguard · Ledger
activity` reads the NOTP and catalog metrics). Domain metrics:
`permguard_notp_operations_total{op,outcome}`, `permguard_notp_operation_seconds`,
`permguard_notp_batch_objects`, `permguard_notp_wire_bytes_total{op,encoding}`,
`permguard_catalog_operations_total{action,outcome}`, `permguard_catalog_zones`,
`permguard_catalog_ledgers` — beside the surface metrics every listener
already publishes.

## Keeping a data plane current

A plane that answers decisions needs the policies to answer from. Two shapes,
both supported, and the choice is about where credentials live:

| Shape | How | Credentials in the PDP |
| --- | --- | --- |
| **Built-in sync** | `dataPlane.mirrors.enabled` on: the plane follows servers, zones and ledgers and keeps `<volume>/data/mirrors/<zone>/<ledger>` current | yes — TLS material, and egress to the control plane |
| **Sidecar** | `permguard pull` beside it writes the volume; the plane serves what it finds | **none**, and no egress at all |

See [Keeping a data plane current](data-plane-mirrors.md) for the configuration,
the guarantees of the loop, and what it reports.
