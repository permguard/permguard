<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Benchmarks

Two kinds live here.
The release benchmark, `permguard-bench`, is what a release publishes and what capacity is configured from.
The k6 scripts (`*.js`) are developer tools for looking at one behaviour at a time against a server you started yourself.

## The release benchmark

`permguard-bench` measures the release's own binaries the way an operator runs them.
It starts `permguard-all-in-one` on loopback with a configuration written for the run, applies `examples/basics` with the `permguard` CLI, waits until the Data Plane answers the dataset, and drives the native PDP.

| Dimension    | What is measured                                                                                    |
| ------------ | --------------------------------------------------------------------------------------------------- |
| interface    | `permguard.api.pdp.native.v1` over HTTP/1.1 with keep-alive and over gRPC with the release's client |
| evidence     | the decision log off (`disabled`) and on with `mode: required`, each on a fresh server              |
| workload     | per profile of the example, the single requests its own tests expect a decision of                  |
| offered load | a ladder of concurrent closed-loop clients, one connection each                                     |

Each step records p50, p95 and p99 latency of the answers, throughput, refusals by code with their own latency, errors by kind, the server's CPU seconds and its peak resident set.
A wrong decision is an error, not an answer.
A refusal is an answer carrying one of the codes a plane answers at a bound (`evaluation_at_capacity`, `load_at_capacity`, `decision_unrecordable`, `unavailable`); a refused connection, a timeout, a `429` or an untyped `503` is an error.
The refusal point is the lowest step at which the plane refused anything.

The clients run on the server's host and share its cores, the run grants `decision.evaluate` to every caller so authentication is not in the latencies, and the measured process is the all-in-one with both planes; the report says all three.
Every run turns the per-address connection bound off, since every client connects from loopback; a run's `--set` can turn it back on.

The report, `permguard.bench.report.v1`, also names what the numbers are true of: the platform, the storage class with a measured `fsync` probe of the volume's directory, the dataset with the digest of its files, and the capacity settings and memory budgets in force.

```sh
cargo build --release -p permguard-all-in-one -p permguard-cli -p permguard-conformance --bins
target/release/permguard-bench run \
  --server target/release/permguard-all-in-one --cli target/release/permguard \
  --storage-class "local NVMe" --out permguard-benchmark.json
target/release/permguard-bench capacity permguard-benchmark.json
```

`--directory` puts the servers' volumes on the storage you want measured; `--set PERMGUARD_NAME=VALUE` runs them under a capacity setting; `--ladder`, `--step-seconds`, `--interfaces` and `--evidence` shape the run.

### What a release publishes

The release pipeline downloads the Linux binaries it has just published, measures them on a GitHub-hosted runner with the full ladder, and attaches `permguard-benchmark.json` to the release.
CI runs a short ladder on every change, so the harness cannot rot between releases.

### Reading capacity off a report

`bench/slo.json` is the published objective: a p99 latency per evidence mode, the headroom a configuration leaves unused, and how slow a refusal may be.
The values were set before the first release report, for a GitHub-hosted runner, and are revisited against each release's report.
`permguard-bench capacity` names, per interface and evidence mode, the highest step at which every workload met the objective with no refusal and no error, and the concurrency limit that leaves the headroom.
When every step met the objective, the ladder ended first and the number is a floor; the output says "at least".
When an interface and evidence mode met it at no step, `capacity` says so and exits non-zero.
A sustained step refused nothing, so the refusal objective does not enter the capacity; it bounds how fast a plane past its capacity says no.
The objective is per request: a boxcarred request of three evaluations is held to the same p99 as a single one.

A report is true of the platform, storage and configuration it names.
Size a deployment from a report taken on its own hardware and storage class; a number measured on one machine is never a default for another.

The defaults the product ships are protective bounds, not capacity promises.
The evaluation pool defaults to the Host's logical cores, read at start; the storage pool, the evaluation queue and the request bound keep fixed defaults that only stop a plane from accumulating work it cannot finish.

## The k6 scripts

| Script        | Looks at                                                       |
| ------------- | -------------------------------------------------------------- |
| `decide.js`   | a decision against a mirrored ledger, with and without the log |
| `temporal.js` | temporal event submission                                      |
| `peak.js`     | the transport's throughput ceiling, nothing behind it          |
| `ladder.js`   | latency at fixed rising rates, open model                      |
| `shed.js`     | the shed layer under overload                                  |
| `grpc.js`     | gRPC `GetInfo`                                                 |
| `tls.js`      | request cost over TLS and mutual TLS                           |
| `hold.js`     | how many connections the plane holds                           |

Each script's header says what it needs running; `task bench:*` runs them.
