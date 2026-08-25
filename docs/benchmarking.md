<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Load testing

The benchmarks live in [`bench/`](../bench) as [k6](https://k6.io) scripts — versioned, reviewed and
repeatable like any other source file. k6 is open source and runs entirely on your machine:
`brew install k6`.

What they call is today's whole public surface — `GET /version`, `GET /health`, gRPC `GetInfo` — and
that is the point: with no domain logic in the way, these numbers measure the transport stack alone
(TCP, TLS, HTTP/1 and HTTP/2, the limits, the routing), which makes them the baseline every future
API's cost is measured against.

## The five runs

| Command | Question it answers | Server to run first |
| --- | --- | --- |
| `task bench:peak` | how many requests per second is the ceiling | `task bench:server` |
| `task bench:ladder` | what latency looks like at fixed rising rates, and where the knee is | `task bench:server` |
| `task bench:shed` | what overload looks like — the excess answered 503 immediately, nothing falling over | `task bench:server:shed` |
| `task bench:grpc` | the same ceiling over gRPC, to compare with HTTP | `task bench:server` |
| `task bench:tls` | what a request costs over TLS/mTLS, handshake measured apart | `task run-as-tls:control` |
| `task bench:hold` | how many connections it can *hold* — sockets, not requests | `task bench:server` |

`bench:server` is the capacity profile: a **release build** with the limits moved out of the way
(`concurrent_requests=100000`, `connections=20000`, `connections_per_peer=0`). Two rules that make
the numbers real rather than pretty:

- **never benchmark a debug build** — its numbers are five to fifty times off;
- **say which limits were in force.** Under defaults, one address may hold at most 256 sockets and
  the shed layer answers 503 beyond 256 requests in flight — so a capacity run must raise them, and
  `bench:server:shed` deliberately *lowers* the request ceiling instead: today's handlers are so
  fast that, by Little's law, the natural in-flight count sits around a dozen, and a ceiling the
  working point never reaches is a defence a benchmark can never see fire.

Throughput is quoted from `peak` (closed loop); latency from `ladder` (open model, fixed arrival
rates) — a closed loop coordinates with the server's slowness and hides the queue, the open model
does not.

## Seeing it in Grafana

The server side needs nothing: the lab's Prometheus already scrapes the plane, and **Permguard ·
Overview** shows requests per second, latency percentiles and refusals for any load you generate
with any tool.

For the client side — what k6 itself felt — push its metrics into the same Prometheus:

```sh
task lab:observability        # Prometheus + Grafana + Loki, watching planes on the host
task bench:server             # in another shell

K6_PROMETHEUS_RW_SERVER_URL=http://127.0.0.1:7591/api/v1/write \
K6_PROMETHEUS_RW_TREND_STATS="p(50),p(95),p(99),avg,max" \
K6_ARGS="-o experimental-prometheus-rw" task bench:ladder
```

**Permguard · Load test** overlays the two views: rate sent versus rate answered, latency the client
felt versus latency the server measured — the gap between those two curves is the network plus the
accept queue, which is the most eloquent chart a benchmark produces. `task bench:grafana` prints the
flags above.

## Against a remote server

The same scripts, one variable:

```sh
PERMGUARD_URL=https://staging.example.com:7556 \
BENCH_CA=path/to/ca.pem task bench:tls
```

Remember what changes: the network is now part of every number, the handshake panels stop being
zero, and the per-address bound on the far side sees *your* address — exempt it, or measure with it.

The compose lab is itself an instance of that rule: through Docker's port forwarding every host
connection reaches the containers as the compose gateway's address, so the `config.docker*.yml`
profiles exempt `172.16.0.0/12` from the per-address bound. Without it, any benchmark beyond 256
connections from the host is measuring the bound, not the plane.

## Tuning knobs

Every script reads environment variables — `BENCH_VUS`, `BENCH_DURATION`, `BENCH_RATE_1..3`,
`BENCH_P95_MS` and the TLS material paths — documented at the top of each file. Two macOS
prerequisites for high-concurrency runs: `ulimit -n 65536` in the shell that runs k6, and keep-alive
left on (it is, by default) so the ephemeral-port range is not exhausted.

Throughput and held connections are different questions with different tests: `peak` and `ladder`
push requests over few connections; `hold` ramps thousands of keep-alive sockets that barely speak,
which is what the connection limits exist to bound. Watch `hold` on the dashboards' connection
panels — the server's own gauge against k6's virtual-user line — plus refusals and process memory.
Two client-side ceilings to rule out first: `ulimit -n`, and the ephemeral ports one source address
has toward one destination — **16,384 by default on macOS** (49152–65535), and the generator hits it
as `can't assign requested address` while the server sits at ~16.3k held connections with zero
refusals of its own. `sudo sysctl -w net.inet.ip.portrange.first=32768` doubles it; past that, the
honest tool is a second generator machine.

One measured lesson worth keeping: on this stack the closed-loop `peak` reports p95 in the
milliseconds while the open-model `ladder` reports it in the tens of microseconds at the same
throughput. Both are true — the closed loop measures its own queue. Quote throughput from `peak`,
latency from `ladder`.

The thresholds in the scripts are tripwires, not targets: a run that exceeds them exits non-zero,
which is what lets a benchmark act as a regression gate once a machine's baseline is known.
