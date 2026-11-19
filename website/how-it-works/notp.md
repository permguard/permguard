---
pageClass: pg-page-concepts
title: NOTP Protocol
description: The Negotiated Object Transfer Protocol moves ledger objects, sends only what is missing and verifies everything on arrival.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">NOTP protocol</div>
  <h1>Only what is missing moves.</h1>
  <p>The Negotiated Object Transfer Protocol: content-addressed, verified on arrival, committed atomically.</p>
</div>

<div class="pgx-discovery" role="img" aria-label="A CLI workspace pushes objects to the Control Plane, which advances refs/main and signs the head. Data Planes pull from the Control Plane, verify and activate.">
  <article><small>WORKSPACE</small><strong>CLI · apply</strong><span>push: negotiate · upload · commit</span></article>
  <i>→</i>
  <article class="pgx-discovery__accent"><small>CONTROL PLANE</small><strong>refs/main · signed head</strong><span>the one place a ref advances</span></article>
  <i>→</i>
  <article><small>DATA PLANES</small><strong>mirror · verify · activate</strong><span>pull: negotiate · fetch · prove</span></article>
</div>

## Push: workspace to Control Plane

<div class="pgx-seq" role="img" aria-label="Push sequence. The CLI sends NegotiatePush with the ref, the new head, the expected ref state and its closure. The Control Plane opens a transfer session and answers with the digests it is missing and the batch limits. The CLI uploads only those objects in batches; the Control Plane decodes, rehashes, lands and pins each one. The CLI sends CommitPush; the Control Plane re-verifies the closure and manifest, checks fast-forward and compare-and-swap, advances the ref once and answers with the signed head statement. The CLI verifies the statement before writing its checkpoint.">
  <div class="pgx-seq__actors"><div><small>CLI</small><strong>apply</strong></div><div><small>CONTROL PLANE</small><strong>ledger</strong></div></div>
  <ol>
    <li class="pgx-seq__msg pgx-seq__msg--right"><b>NegotiatePush</b><span>ref · new head · expected ref · closure</span></li>
    <li class="pgx-seq__msg pgx-seq__msg--left"><b>missing digests</b><span>transfer id · batch limits · reservation · expiry</span></li>
    <li class="pgx-seq__msg pgx-seq__msg--right"><b>UploadObjects × n</b><span>only the missing objects, in batches</span></li>
    <li class="pgx-seq__act pgx-seq__act--right"><span>decode · rehash · land · pin</span></li>
    <li class="pgx-seq__msg pgx-seq__msg--right"><b>CommitPush</b><span>expected ref: counter + ref digest</span></li>
    <li class="pgx-seq__act pgx-seq__act--right"><span>closure · manifest · fast-forward · compare-and-swap</span></li>
    <li class="pgx-seq__msg pgx-seq__msg--left"><b>signed head</b><span>head · counter · ref digest · statement</span></li>
    <li class="pgx-seq__act pgx-seq__act--left"><span>verify · checkpoint</span></li>
  </ol>
</div>

Negotiation is a hint; the commit is the authority.
At commit the Control Plane validates again against what it holds: the whole closure, the manifest, fast-forward and the expected ref state, then advances the ref once.
A ref that moved in between is refused `ref_conflict` (`409`): pull, reconcile, apply again.

## Pull: Control Plane to Data Planes

<div class="pgx-seq" role="img" aria-label="Pull sequence. The Data Plane sends NegotiatePull with the ref, its verified checkpoint and the objects it has. The Control Plane answers with the signed head statement and the missing digests. The Data Plane verifies the signature and the counter before fetching anything, then sends FetchObjects for the missing digests and receives the canonical objects. It rehashes every object, proves the closure and the manifest, moves its checkpoint and activates the new version.">
  <div class="pgx-seq__actors"><div><small>DATA PLANE</small><strong>mirror</strong></div><div><small>CONTROL PLANE</small><strong>ledger</strong></div></div>
  <ol>
    <li class="pgx-seq__msg pgx-seq__msg--right"><b>NegotiatePull</b><span>ref · checkpoint · objects held</span></li>
    <li class="pgx-seq__msg pgx-seq__msg--left"><b>signed head + missing digests</b><span>head · counter · ref digest · statement</span></li>
    <li class="pgx-seq__act pgx-seq__act--left"><span>verify signature · counter first</span></li>
    <li class="pgx-seq__msg pgx-seq__msg--right"><b>FetchObjects</b><span>the missing digests, in batches</span></li>
    <li class="pgx-seq__msg pgx-seq__msg--left"><b>canonical objects</b><span>immutable bytes</span></li>
    <li class="pgx-seq__act pgx-seq__act--left"><span>rehash · prove closure · checkpoint · activate</span></li>
  </ol>
</div>

The signed head is checked before a single object is fetched, and the checkpoint moves only after the whole closure is proven.
A Data Plane pulls through its Host's `policy.mirror` membership task, and every accepted commit sends a `WatchRefs` hint to the members watching that ledger.
A hint carries no policy: it only starts the same verified pull now instead of at the next round.
`permguard pull` runs the same cycle and writes the files between proof and checkpoint, so a failed write never leaves the checkpoint ahead of the disk.

## Why a dedicated protocol

<div class="pgx-principles">
  <article><span>01</span><h3>Content addressed</h3><p>A digest names exact canonical bytes. Both sides compute it the same way.</p></article>
  <article><span>02</span><h3>Only missing travels</h3><p>Negotiation compares closures; the answer is the list of digests the other side lacks.</p></article>
  <article><span>03</span><h3>Verified on arrival</h3><p>Every object is decoded and rehashed; the closure must be complete before anything is used.</p></article>
  <article><span>04</span><h3>Atomic ref advance</h3><p>One compare-and-swap per ledger, a counter that rises by one, a signed statement for the result.</p></article>
  <article><span>05</span><h3>Conflicts refused</h3><p>A stale expected ref, a rewrite of history, a ledger two sources claim: each is refused, never merged.</p></article>
  <article><span>06</span><h3>Resumable and bounded</h3><p>A push is a transfer session: batched within advertised limits, held against quota, pinned against garbage collection.</p></article>
</div>

## Discovered, not configured

The Control Plane advertises the whole NOTP surface in its server configuration.

```sh
curl -s http://127.0.0.1:6443/.well-known/server-configuration | jq .notp
```

```json
{
  "media_type": "application/vnd.permguard.notp.v1+cbor",
  "compression": "deflate",
  "ref_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/refs/{ref}",
  "push_negotiation_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/push/negotiate",
  "push_commit_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/push/commit",
  "pull_negotiation_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/pull/negotiate",
  "object_upload_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/objects",
  "object_fetch_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/objects/fetch"
}
```

| Endpoint                    | HTTP                  | gRPC `GitLikeStore` |
| --------------------------- | --------------------- | ------------------- |
| `ref_endpoint`              | `GET refs/{ref}`      | `GetRef`            |
| `push_negotiation_endpoint` | `POST push/negotiate` | `NegotiatePush`     |
| `object_upload_endpoint`    | `POST objects`        | `UploadObjects`     |
| `push_commit_endpoint`      | `POST push/commit`    | `CommitPush`        |
| `pull_negotiation_endpoint` | `POST pull/negotiate` | `NegotiatePull`     |
| `object_fetch_endpoint`     | `POST objects/fetch`  | `FetchObjects`      |

Head statements verify against the key set at `jwks_uri` (`GetKeyRing` over gRPC).
Both transports carry the same CBOR messages.
Each verb is one step of the two diagrams above.
A request body not declared as `application/vnd.permguard.notp.v1+cbor` is refused before it is read, and every refusal names a stable class and code.

## The CLI speaks it

```sh
# read and check the discovery document
permguard remote add origin https://permguard.internal:6443
# bind the workspace to a ledger and materialize it
permguard checkout origin/delivery/release-pipeline
# NegotiatePush → UploadObjects → CommitPush
permguard apply -m "require a signed artifact before approval"
# NegotiatePull → FetchObjects
permguard pull
# signed head, counter, local closure
permguard verify
```

Add `-v` to any of them to narrate what it does, on stderr.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./policy-storage"><span>Previous</span><strong><b aria-hidden="true">←</b> Git-like Versioning</strong></a>
  <a class="pgx-pager__next" href="./policy-lifecycle"><span>Next</span><strong>Policy Delivery <b aria-hidden="true">→</b></strong></a>
</nav>
