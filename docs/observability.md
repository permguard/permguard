<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Observability

Permguard exposes health and metrics on a **port of its own**, and that is deliberate: metrics
describe the inside of the process and health tells an attacker when it is struggling, so neither
belongs on the port that faces the world. It is HTTP, because Prometheus scrapes over HTTP and a
kubelet probes over HTTP — serving it over gRPC would mean every operator needs a custom client to
read a number.

| Endpoint | Answers | A failure means |
| --- | --- | --- |
| `GET /healthz` | is this process wedged | restart me |
| `GET /readyz` | should I be sent work | stop routing to me |
| `GET /metrics` | everything measured | nothing — it is always `200`, even when unhealthy |

Liveness and readiness are separate on purpose. `/readyz` goes false at the very first instant of
shutdown — before anything is closed — so a load balancer stops routing while the process is still
able to finish what it already has. Reporting one number for both loses requests at every deploy.

`/metrics` answers `200` even when the process reports itself unhealthy: a scrape that fails is a
scrape with no numbers in it, and the numbers explaining *why* something is unhealthy are exactly the
ones wanted at that moment.

## What is measured

| Metric | Type | Labels | What it is for |
| --- | --- | --- | --- |
| `permguard_up` | gauge | — | The process reports itself live. Zero means restart. |
| `permguard_ready` | gauge | — | The process is willing to be sent work. |
| `permguard_surface_requests_total` | counter | `surface`, `method`, `status` | Everything answered, and how it ended. |
| `permguard_surface_request_seconds` | histogram | `surface`, `method` | How long it took. Measured around everything below the transport layer, including the wait for a concurrency slot — the time a client actually feels, and the time a handler-only measurement hides. |
| `permguard_surface_connections` | gauge | `surface` | Held right now. Watch it against the configured ceiling. |
| `permguard_surface_connections_accepted_total` | counter | `surface` | Accepted. |
| `permguard_surface_connections_refused_total` | counter | `surface`, `scope` | Turned away: `scope="pool"` is the surface at its limit, `scope="peer"` is one address at its share. **Any value above zero is worth an alert**: it is the first thing that happens under a connection flood, and it happens long before the process shows any other sign. |
| `permguard_tls_certificate_expiry_timestamp_seconds` | gauge | `surface` | When the certificate stops being valid. |
| `permguard_keys_active` | gauge | `realm`, `role` | Whether an issuer has an active signing key. |

Three families are worth their own pages, because each answers a question of
its own: the **synchronization loop** (`permguard_sync_*` — is my policy
current, what is growing) is documented in
[Keeping a data plane current](data-plane-mirrors.md), the **decision path**
(`permguard_authz_*` — is it answering, is it warm, is anything unserveable) in
[Answering decisions](authorization-check.md), and the **decision log**
(`permguard_decisions_*`) in [Decision logs](decision-logs.md).

Of the decision-log family, two are worth an alert on their own.
**`permguard_decisions_unshipped_records`** is the one to watch: a number that
climbs and does not come back is a shipper that is not shipping, and it is
visible long before the spool is full and the stream has to end. And
**`permguard_decisions_shipped_total{outcome="rejected"}`** above zero is an
incident rather than a trend — the control plane refused a batch on its merits,
and no amount of retrying changes that answer. Both are read by the two
dedicated dashboards the lab provisions:

| Dashboard | Answers |
| --- | --- |
| **Permguard · Control plane** | zones and ledgers held, pushes and pulls, transfer sizes, disk per zone, every NOTP exchange |
| **Permguard · Data plane** | decisions and their latency, cache hit rate and occupancy, blocked ledgers, synchronization rounds and mirror freshness, disk per zone |

Certificate expiry is a **timestamp**, not "days remaining", and that is the interesting design
decision here. The registry holds a value written when the certificate was loaded and read whenever
somebody scrapes; "days remaining" would be correct at the moment it was written and quietly wrong
for every scrape after — a certificate with two days left would still be reporting thirty a month
later. A timestamp is true whenever it is read, and the subtraction happens in the query:

```promql
(permguard_tls_certificate_expiry_timestamp_seconds - time()) / 86400 < 30
```

The `surface` label is the component: `control-plane`, `data-plane`, `telemetry`. The telemetry
surface measures itself, so Prometheus scraping Permguard appears in Permguard's own request rate.

## The local lab

One command brings up the planes, Prometheus, Loki and Grafana, with dashboards already provisioned:

```sh
task lab:up          # or: make lab-up
```

| Where | Address |
| --- | --- |
| Grafana | <http://127.0.0.1:7590> |
| Prometheus | <http://127.0.0.1:7591> |
| Loki | <http://127.0.0.1:7592> |
| Control plane | <http://127.0.0.1:7556> |
| Data plane | <http://127.0.0.1:7656> |

Grafana opens on **Permguard · Overview**: liveness and readiness, request rate by surface and by
status, latency percentiles, connections held, connections refused, and days until the certificate
expires. **Permguard · Logs** is the same run seen through Loki — records per second by level and by
`event.name`, warnings and errors, and the audit trail. There is no login: it is a lab on loopback,
and a login screen between a demo and its dashboard buys nothing.

The lab's ports sit in Permguard's own range on purpose. Grafana's convention is `3000`, and `3000` is
the most contended port on a developer's machine — a lab whose first act is to fail to bind is not a
lab. Every port can still be moved:

```sh
PERMGUARD_GRAFANA_PORT=3000 task lab:up
```

`PERMGUARD_PROMETHEUS_PORT`, `PERMGUARD_LOKI_PORT`, `PERMGUARD_CONTROL_HTTP_PORT` and
`PERMGUARD_DATA_HTTP_PORT` work the same way.

### Watching a runtime you started yourself

The interesting mode. Start only the observability stack, and point it at the planes you are running
from your editor with `task run:all`:

```sh
task run:all                 # in one shell — cargo, your code, your breakpoints
task lab:observability       # in another: Prometheus, Grafana, Loki only
```

Prometheus is configured for **both** sets of targets at once — the compose services by name, and the
host through `host.docker.internal` — so nothing needs reconfiguring when you switch. A target that
is not running is `up == 0` and nothing else. The dashboards select on the `component` label rather
than on the job, so they do not care which one answered.

What does *not* work in this mode is logs: a plane started with `task run:all` writes to your
terminal, and nothing is shipping that to Loki. The metrics are complete; the log panels are empty
until the planes run in containers.

### The all-in-one, and the TLS profiles

```sh
task lab:all         # the single-process runtime instead of the two planes
task lab:down        # stop, keeping the stored metrics and logs
task lab:clean       # stop AND discard them — the next up starts clean
task lab:logs        # follow everything, or SERVICE=grafana for one
```

The lab's planes run the `config.docker.yml` profile, which logs JSON — which is what makes the level
and the `event.name` queryable in Loki rather than buried in a string. The TLS and mutual-TLS
profiles are local rather than containerised for now: `task run-as-tls:all` and
`task run-as-mtls:all`, watched with `task lab:observability`.

## Alerts

`lab/prometheus/rules.yml` carries the rules worth having, evaluated by the lab's Prometheus so they
can be reviewed before being copied anywhere real: not ready, not live, target down, connections
refused, 5xx rate, authorization audit loss, mirror staleness and sync failures, decision-log
backlog and loss, batch refusals, stream closure, and certificate/CRL expiry. There is no
Alertmanager — a lab does not need to page anybody.

The Helm chart can render the same production baseline as a Prometheus Operator
`PrometheusRule` when `metrics.prometheusRule.enabled=true`. The rule object is off by default
because the CRD belongs to the cluster's monitoring stack. The default thresholds are starting
points: copy them into the platform's alert route and tune them against real traffic.

## In a cluster

See [Kubernetes](kubernetes.md). The chart puts the telemetry port on a service of its own, annotates
it for Prometheus, and can render a `ServiceMonitor` for the Prometheus Operator.
