---
pageClass: pg-page-concepts
title: Verifiable Evidence
description: Every decision leaves a canonical, signed and chained record that anyone holding the keys can verify.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Verifiable evidence</div>
  <h1>Every decision, on record.</h1>
  <p>Who asked, for what, under which policy, and the answer. Signed, chained, and verifiable by someone who does not trust the plane that wrote it.</p>
</div>

<div class="pgx-chain">
  <svg class="pgx-hv pgx-chain__wide" viewBox="0 0 780 290" role="img" aria-label="Three records of one Data Plane stream. Each record's prev is the SHA-256 digest of the record before it: sequence 1 is a marker whose prev is the genesis value, sequence 2 is the decision 01a1f111, sequence 3 the next one. The digest of the last record is the batch head, signed with EdDSA under the Host's data.attest key, and the signed batch is shipped over decisions.ship to the Control Plane, which verifies it and serves reads. Changing one byte of sequence 2 breaks the chain at sequence 3, or the head and its signature.">
    <g class="pgx-hv__node"><rect x="0.5" y="24.5" width="160" height="112" rx="14"/><text class="pgx-hv__k" x="80" y="58" text-anchor="middle">SEQ 1 · MARKER</text><text class="pgx-hv__s" x="80" y="84" text-anchor="middle">build · sampling</text><text class="pgx-hv__m" x="80" y="108" text-anchor="middle">prev = genesis</text></g>
    <g class="pgx-hv__node pgx-chain__focus"><rect x="214.5" y="24.5" width="160" height="112" rx="14"/><text class="pgx-hv__k" x="294" y="58" text-anchor="middle">SEQ 2 · DECISION</text><text class="pgx-hv__s" x="294" y="84" text-anchor="middle">01a1f111…</text><text class="pgx-hv__m" x="294" y="108" text-anchor="middle">prev = digest(1)</text></g>
    <g class="pgx-hv__node"><rect x="428.5" y="24.5" width="160" height="112" rx="14"/><text class="pgx-hv__k" x="508" y="58" text-anchor="middle">SEQ 3 · DECISION</text><text class="pgx-hv__s" x="508" y="84" text-anchor="middle">the next answer</text><text class="pgx-hv__m" x="508" y="108" text-anchor="middle">prev = digest(2)</text></g>
    <g class="pgx-hv__node pgx-chain__focus"><rect x="639.5" y="24.5" width="140" height="112" rx="14"/><text class="pgx-hv__k" x="710" y="58" text-anchor="middle">SIGNATURE</text><text class="pgx-hv__s" x="710" y="84" text-anchor="middle">EdDSA</text><text class="pgx-hv__m" x="710" y="108" text-anchor="middle">data.attest key</text></g>
    <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M166 80 H204"/><path class="pgx-chain__arrow" d="M204 75 L212 80 L204 85 Z"/><text class="pgx-hv__m" x="188" y="68" text-anchor="middle">digest</text>
    <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M380 80 H418"/><path class="pgx-chain__arrow" d="M418 75 L426 80 L418 85 Z"/><text class="pgx-hv__m" x="402" y="68" text-anchor="middle">digest</text>
    <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M594 80 H629"/><path class="pgx-chain__arrow" d="M629 75 L637 80 L629 85 Z"/><text class="pgx-hv__m" x="614" y="68" text-anchor="middle">head</text>
    <path class="pgx-chain__bracket" d="M1 148 V156 H588 V148 M294 156 V164"/>
    <text class="pgx-hv__m" x="294" y="184" text-anchor="middle">one batch · seq 1–3 · a Merkle root over their digests</text>
    <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M710 142 V200"/><path class="pgx-chain__arrow" d="M705 200 L710 208 L715 200 Z"/><text class="pgx-hv__m" x="700" y="178" text-anchor="end">decisions.ship</text>
    <g class="pgx-hv__node"><rect x="639.5" y="214.5" width="140" height="64" rx="14"/><text class="pgx-hv__k" x="710" y="240" text-anchor="middle">CONTROL PLANE</text><text class="pgx-hv__s" x="710" y="264" text-anchor="middle">verify · serve</text></g>
    <text class="pgx-chain__warn" x="0" y="230">Change one byte of seq 2:</text>
    <text class="pgx-hv__m" x="0" y="252">the chain breaks at seq 3,</text>
    <text class="pgx-hv__m" x="0" y="272">or the head and its signature fail.</text>
  </svg>
  <svg class="pgx-hv pgx-chain__compact" viewBox="0 0 340 715" role="img" aria-label="Three records of one Data Plane stream. Each record's prev is the SHA-256 digest of the record before it: sequence 1 is a marker whose prev is the genesis value, sequence 2 is the decision 01a1f111, sequence 3 the next one. The digest of the last record is the batch head, signed with EdDSA under the Host's data.attest key, and the signed batch is shipped over decisions.ship to the Control Plane, which verifies it and serves reads. Changing one byte of sequence 2 breaks the chain at sequence 3, or the head and its signature.">
    <g class="pgx-hv__node"><rect x="20.5" y="0.5" width="300" height="92" rx="14"/><text class="pgx-hv__k" x="170" y="30" text-anchor="middle">SEQ 1 · MARKER</text><text class="pgx-hv__s" x="170" y="56" text-anchor="middle">build · sampling</text><text class="pgx-hv__m" x="170" y="78" text-anchor="middle">prev = genesis</text></g>
    <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M170 98 V130"/><path class="pgx-chain__arrow" d="M165 130 L170 138 L175 130 Z"/><text class="pgx-hv__m" x="184" y="122">digest</text>
    <g class="pgx-hv__node pgx-chain__focus"><rect x="20.5" y="140.5" width="300" height="92" rx="14"/><text class="pgx-hv__k" x="170" y="170" text-anchor="middle">SEQ 2 · DECISION</text><text class="pgx-hv__s" x="170" y="196" text-anchor="middle">01a1f111…</text><text class="pgx-hv__m" x="170" y="218" text-anchor="middle">prev = digest(1)</text></g>
    <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M170 238 V270"/><path class="pgx-chain__arrow" d="M165 270 L170 278 L175 270 Z"/><text class="pgx-hv__m" x="184" y="262">digest</text>
    <g class="pgx-hv__node"><rect x="20.5" y="280.5" width="300" height="92" rx="14"/><text class="pgx-hv__k" x="170" y="310" text-anchor="middle">SEQ 3 · DECISION</text><text class="pgx-hv__s" x="170" y="336" text-anchor="middle">the next answer</text><text class="pgx-hv__m" x="170" y="358" text-anchor="middle">prev = digest(2)</text></g>
    <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M170 378 V410"/><path class="pgx-chain__arrow" d="M165 410 L170 418 L175 410 Z"/><text class="pgx-hv__m" x="184" y="402">head</text>
    <g class="pgx-hv__node pgx-chain__focus"><rect x="20.5" y="420.5" width="300" height="92" rx="14"/><text class="pgx-hv__k" x="170" y="450" text-anchor="middle">SIGNATURE · SEQ 1–3</text><text class="pgx-hv__s" x="170" y="476" text-anchor="middle">EdDSA</text><text class="pgx-hv__m" x="170" y="498" text-anchor="middle">data.attest key</text></g>
    <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M170 518 V550"/><path class="pgx-chain__arrow" d="M165 550 L170 558 L175 550 Z"/><text class="pgx-hv__m" x="184" y="542">decisions.ship</text>
    <g class="pgx-hv__node"><rect x="20.5" y="560.5" width="300" height="72" rx="14"/><text class="pgx-hv__k" x="170" y="588" text-anchor="middle">CONTROL PLANE</text><text class="pgx-hv__s" x="170" y="614" text-anchor="middle">verify · serve</text></g>
    <text class="pgx-chain__warn" x="170" y="664" text-anchor="middle">Change one byte of seq 2:</text>
    <text class="pgx-hv__m" x="170" y="686" text-anchor="middle">the chain breaks at seq 3,</text>
    <text class="pgx-hv__m" x="170" y="708" text-anchor="middle">or the head and its signature fail.</text>
  </svg>
  <div class="pgx-chain__formula">
    <code>digest(n) = SHA-256("permguard.decision.v1\n" ‖ JCS(record n))</code>
    <code>prev(1) = sha256:000…0</code>
    <code>prev(n) = digest(n − 1)</code>
  </div>
</div>

Records are canonical JSON (RFC 8785), so one record has exactly one digest.
The digest is computed, never transmitted: a digest carried beside the record would be a field anyone could make agree with a lie.
One signature per batch covers every record in it, because the head is the digest of the last record and the chain binds each one to it.

## What a record holds

| Question            | Record member                                                                     |
| ------------------- | --------------------------------------------------------------------------------- |
| Who?                | `subject`, and `principal` when the request names one                             |
| What?               | `action`                                                                          |
| On which resource?  | `resource`                                                                        |
| Under which policy? | `store`: zone, ledger and commit; `policies`: the ones that decided               |
| Permit or deny?     | `decision`, and `outcome`: `permit`, `deny`, `deny_by_default` or `indeterminate` |
| Which decision?     | `id`, the same `context.id` the caller received                                   |
| Where in history?   | `stream`: the Host id and its run; `seq`; `prev`                                  |

Identifiers are pseudonymised, and what the caller sent is kept in `inputs` as keyed tags.
An attribute is recorded in clear only when the deployment names it in the decision log's `include`.
Policy text is never recorded.
Denials and errors are never sampled; a deployment that samples permits says so in the `marker` that governs the records after it.

## Durable before the answer

| Mode                         | Before the answer leaves                                    | When the record cannot be written     |
| ---------------------------- | ----------------------------------------------------------- | ------------------------------------- |
| `required` · shipped default | the record and its marker are durable on the plane's volume | the decision is refused `unavailable` |
| `disabled`                   | no record is promised                                       | not applicable                        |

`best-effort` is refused at start until its loss record is defined.
Shipping to the Control Plane happens after the answer, off the decision path: a Control Plane that is down costs spool, not availability.
Only past the spool's bound are decisions refused, never answered without a record.

The answer says what it waited for and where its record sits.
A real answer of the Data Plane, abridged:

```json
{
  "decision": true,
  "request_id": "quickstart-1",
  "context": {
    "id": "01a1f111-df65-77cf-b171-3facea0cbc27",
    "policies": ["92efe24a-8620-8bcd-b026-a19c1f440c45"],
    "evidence": {
      "mode": "required",
      "status": "durable",
      "record_id": "01a1f111-df65-77cf-b171-3facea0cbc27",
      "position": {
        "host_id": "01a1f110-6550-759a-8d3a-b48851feacbb",
        "run": "683d0666310e237b02cd1c2ea4106c6d",
        "sequence": "2"
      }
    }
  }
}
```

<div class="pgx-note"><strong>No timestamp guessing.</strong><span><code>record_id</code> is the decision id; <code>position</code> names the Host, its run and the record's sequence.</span></div>

## Read it back

The Control Plane answers reads from what its Data Planes ship to it, as signed batches over the Host's `decisions.ship` task.
An all-in-one ships to its own Control Plane in-process, so its reads answer within seconds of the decision.

```sh
permguard decisions list --zone quickstart --ledger policies
permguard decisions tail --zone quickstart --ledger policies --follow
permguard decisions get 01a1f111-df65-77cf-b171-3facea0cbc27 --zone quickstart --ledger policies
```

A page carries `next` and `more`.
Resume with `--from <next>` and stop on `more`, never on an empty page: every page carries a `next`, even the last one.
The offset is opaque and bound to the scope that issued it, so one tenant's offset is refused under another.
The Control Plane keeps no cursor of its own, so two readers never interfere.

The position reads one producer's whole stream: `--pdp` takes its `host_id`, `--instance` its `run`.

```sh
permguard decisions list \
  --pdp 01a1f110-6550-759a-8d3a-b48851feacbb \
  --instance 683d0666310e237b02cd1c2ea4106c6d
```

A stream that stops moving is never silent: the Host reports `degraded: shipping` in its status, naming the stream, and sets `permguard_stream_shipping_stalled_seconds`.

## Verify it

```sh
# the chain, and the signatures against the producer's published key set
permguard decisions list --zone quickstart --ledger policies \
  --verify --keys data-plane-keys.json

# which key signed which stretch of the stream, public keys included
permguard decisions signers \
  --pdp 01a1f110-6550-759a-8d3a-b48851feacbb \
  --instance 683d0666310e237b02cd1c2ea4106c6d

# a snapshot, verified offline without contacting a server
permguard decisions export --zone quickstart --ledger policies -o json > decisions.json
permguard decisions verify --file decisions.json --keys data-plane-keys.json
```

Without `--keys`, `--verify` proves what the records alone can: a contiguous, unaltered chain.
With `--keys`, it also proves that a key of that set signed the batches, which makes the result independent of the server that served them.
The report says which of the two it checked.

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card"><span>01</span><h3>Integrity</h3><p>The canonical bytes still produce the digests the chain and the signed head commit to.</p></article>
  <article class="pgx-card"><span>02</span><h3>Order</h3><p>Sequence and <code>prev</code> make a gap, a reorder or a fork in the producer's history visible.</p></article>
  <article class="pgx-card pgx-card--accent"><span>03</span><h3>Attribution</h3><p>The signing key, the ledger commit and the deciding policies stay explicit.</p></article>
</div>

## What it does not prove

A record proves what the producer asserted and which key asserted it, subject to that key's custody.
It does not prove that the policy was right, that the Host was uncompromised, a person's intent or a legal conclusion.

<div class="pgx-deploy">
  <article><div class="pgx-kicker">Evidence · available</div><h3>Trace the decision</h3><p>Where an answer came from: the bytes, their order, the signer, the policy version and the deciding policies.</p></article>
  <article><div class="pgx-kicker">Trust Plane · in development</div><h3>Continue authority</h3><p>Whether authority may cross into the next execution. Traceability does not grant it: that is a separate protocol and policy question.</p></article>
</div>

See the [Trust Plane](../trust-plane) for that boundary.

## Into your SIEM

[Permguard Admin](./install#permguard-admin) exports its Decision logs page, whatever the search, the period and the outcome filter leave, in two formats:

| Format     | Holds                                                                                                           |
| ---------- | --------------------------------------------------------------------------------------------------------------- |
| JSON Lines | every record whole, one per line, as synced from the Control Plane                                              |
| CSV        | one row per decision, the fields a spreadsheet sorts by; a cell that would read as a formula gets a quote first |

For a pipeline, `permguard decisions export` writes every page of a snapshot to standard output.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./decision-lifecycle"><span>Previous</span><strong><b aria-hidden="true">←</b> Decision Path</strong></a>
  <a class="pgx-pager__next" href="./bring-your-own-data-plane"><span>Next</span><strong>Bring Your Own Data Plane <b aria-hidden="true">→</b></strong></a>
</nav>
