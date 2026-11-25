---
pageClass: pg-page-concepts
title: Decisions & Evidence
description: Ask a Data Plane for a decision, then read, follow, export and verify the decisions and events it recorded, with the permguard CLI.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero pgx-cli-hero">
  <div class="pgx-kicker">Command Line</div>
  <h1>Ask, read back, prove.</h1>
  <p><code>check</code> asks a Data Plane for one decision; <code>decisions</code> and <code>events</code> read back what was recorded, and verify it.</p>
</div>

Every decision leaves a signed record chained to the one before it, and the events a Data Plane receives are kept and verified the same way.
`check` reaches the Data Plane at `--data-endpoint`; `decisions` and `events` read the records through the Control Plane at `--control-endpoint`.
An export can be verified later, offline, against the producers' published keys: see [Verifiable Evidence](../how-it-works/evidence) for what is proved.

## check

Asks a Data Plane for an authorization decision.

```sh
permguard check [OPTIONS]
```

| Flag                   | Meaning                                                                                   |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| `-f, --file <FILE>`    | the request document, the `permguard.api.pdp.native.v1` payload; `-` reads standard input |
| `--zone <ZONE>`        | the zone to ask about, overriding the workspace and the document                          |
| `--ledger <LEDGER>`    | the ledger to ask about, overriding the workspace and the document                        |
| `--profile <PROFILE>`  | which of the ledger's profiles to evaluate; `default` when absent                         |
| `--subject <TYPE:ID>`  | whom the decision is about                                                                |
| `--action <NAME>`      | the operation, such as `read`                                                             |
| `--resource <TYPE:ID>` | what it targets                                                                           |
| `--context <JSON>`     | environmental attributes, as a JSON object                                                |
| `--ignore-workspace`   | sends the document exactly as written, even inside a workspace                            |

```sh
permguard check -f request.json
cat request.json | permguard check -f -
permguard check -f request.json --zone delivery --ledger release-pipeline -o json
permguard check --profile pipeline --subject Workload:ci-pipeline --action artifact:upload --resource Release:v2.4.0
```

The ledger asked about is the first one named: `--zone` and `--ledger` together, then the workspace you stand in, then the request document.
A `deny` is an answer, not a failure: it prints as a decision and exits 0.
`permguard test --remote` runs a workspace's test cases against the tracked Data Plane in the same way; see [Workspaces & Policies](./workspaces#test).

## decisions

Reads the decisions a Data Plane recorded.

```sh
permguard decisions list [OPTIONS]
permguard decisions tail [OPTIONS]
permguard decisions get [OPTIONS] <ID>
permguard decisions signers [OPTIONS]
permguard decisions export [OPTIONS]
permguard decisions verify [OPTIONS] --file <FILE> --keys <FILE>
```

| Command             | What it does                                                                      |
| ------------------- | --------------------------------------------------------------------------------- |
| `decisions list`    | lists a page of decisions, oldest first                                           |
| `decisions tail`    | follows the decisions as they arrive; `--follow` keeps reading at the end         |
| `decisions get`     | shows one decision, by the id the caller was given back in `context.id`           |
| `decisions signers` | shows which key signed which stretch of one producer stream, public keys included |
| `decisions export`  | reads in bulk, resumably: every page, from an offset, to standard output          |
| `decisions verify`  | verifies an export offline: the chain or the inclusion paths, and the signatures  |

The reading commands share these flags:

| Flag                        | Meaning                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------- |
| `--zone`, `--ledger`        | the ledger whose decisions to read, overriding the workspace                        |
| `--pdp <PDP_ID>`            | reads one producer's whole stream instead of one tenant's records                   |
| `--instance <INSTANCE>`     | which incarnation of that producer                                                  |
| `--from <OFFSET>`           | where to resume: the `next` a previous page returned                                |
| `--limit <N>`               | how many decisions to read at once, at least 1; marker events are not counted; 100  |
| `--since <TIMESTAMP>`       | only decisions at or after this RFC 3339 timestamp                                  |
| `--decision <DECISION>`     | only `permit`, `deny` or `indeterminate`                                            |
| `--verify`                  | re-computes the chain, and the signatures when a key set is given                   |
| `--keys <FILE>`             | the producer's published key set, a JWKS file, for `--verify`                       |
| `--ignore-workspace`        | reads exactly what is asked, even inside a workspace                                |
| `--from-seq`, `--until-seq` | `signers`: the range of offsets to name keys for, inclusive; to the head by default |

Paginate on `more`, not on `next`: every page carries a `next`, even when nothing follows it.
With `--follow`, a Control Plane that supports it holds the read open until the next decision arrives, so a followed tail shows each decision moments after its answer; an older Control Plane is asked again every second.

```sh
permguard decisions list --zone delivery --ledger release-pipeline
permguard decisions list --decision deny --since 2026-08-01T00:00:00Z
permguard decisions tail --decision deny --follow
permguard decisions get 0198f3f2-7c1a-7e2b-9f4c-1d2e3a4b5c6d -o json
permguard decisions signers --pdp pdp-eu-1 --instance 7f3c --from-seq 1000 -o json
```

### Exporting and verifying decisions

```sh
permguard decisions export -o json > decisions.json
permguard decisions export --pdp pdp-eu-1 --instance 7f3c --verify --keys data-plane-keys.json
permguard decisions verify --file decisions.json --keys data-plane-keys.json
```

`decisions verify` reads a JSON or YAML archive that `decisions export` produced, without contacting a server.
A verification that does not hold exits 2.

## events

Reads the events a Data Plane recorded, and verifies them.

```sh
permguard events list [OPTIONS]
permguard events tail [OPTIONS]
permguard events get [OPTIONS] <EVENT_ID>
permguard events signers [OPTIONS]
permguard events export [OPTIONS]
permguard events verify [OPTIONS]
```

| Command          | What it does                                                                                          |
| ---------------- | ----------------------------------------------------------------------------------------------------- |
| `events list`    | lists a page of events, oldest first                                                                  |
| `events tail`    | follows the events as they arrive; `--follow` keeps reading at the end                                |
| `events get`     | shows one occurrence, by the identifier its submission stated                                         |
| `events signers` | shows which key signed which stretch of each producer stream, public keys included                    |
| `events export`  | reads a finite snapshot in bulk, resumably: every page, to standard output                            |
| `events verify`  | verifies what is held, or an export with `--file`: the chain, the Merkle inclusion and the signatures |

Beside `--zone`, `--ledger`, `--instance`, `--from`, `--limit`, `--verify`, `--keys` and `--ignore-workspace`, which work as for decisions, the event commands take:

| Flag                             | Meaning                                                                           |
| -------------------------------- | --------------------------------------------------------------------------------- |
| `--producer <PRODUCER>`          | reads one producer's whole stream instead of one tenant's records                 |
| `--producer-class <CLASS>`       | the registered producer class, when reading a stream; the Data Plane's by default |
| `--limit-bytes <BYTES>`          | how many bytes to read at once; the server clamps both bounds                     |
| `--event-type <TYPE>`            | only events of these registered types; repeatable                                 |
| `--kind <KIND>`                  | only events of this runtime kind: Dogwood's `request`, `response`, `error`        |
| `--profile <PROFILE>`            | only events decided under this profile                                            |
| `--policy-partition <PARTITION>` | only events addressed to this policy partition                                    |
| `--since`, `--until`             | only events at or after, at or before, an RFC 3339 instant                        |
| `--history <DIGEST>`             | only events in this Dogwood history partition, by the key's digest                |
| `--after <CURSOR>`               | `signers`: resumes after a truncated page, as `class/producer/instance`           |
| `--file <FILE>`                  | `verify`: an archive `events export` produced, verified without a server          |

```sh
permguard events list --zone acme --ledger agent-governance
permguard events list --event-type permguard.dogwood.event.v1 --kind request
permguard events tail --kind error --follow
permguard events export -o json > events.json
permguard events verify --file events.json --keys plane-keys.json -o json
```

## evidence anchors

Prints the retained prefix anchors of a ledger's decision and event streams, and the ranges they cover, as the Host keeps them.
It reaches the Host listener at `--host-endpoint`, and takes the zone and the ledger by id.

```sh
permguard evidence anchors [OPTIONS] <ZONE> <LEDGER>
```

```sh
permguard evidence anchors 0198f3bb-0000-7000-8000-000000000002 0198f3bb-0000-7000-8000-000000000003
```

A stream type the Host does not serve, and a ledger its streams do not list, are said so in the report.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./zones-and-ledgers"><span>Previous</span><strong><b aria-hidden="true">←</b> Zones &amp; Ledgers</strong></a>
  <a class="pgx-pager__next" href="./authority"><span>Next</span><strong>Authority <b aria-hidden="true">→</b></strong></a>
</nav>
