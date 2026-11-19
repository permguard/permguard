---
pageClass: pg-page-concepts
title: Bring Your Own Data Plane
description: Run the Permguard Data Plane by default; build your own only when the decision must live in your process or at a specialised edge.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Bring your own Data Plane</div>
  <h1>Same ledger. Your runtime.</h1>
  <p>The Permguard Data Plane is the supported default. Build your own only when the decision must live inside your process or at a specialised edge.</p>
</div>

<div class="pgx-byo-flow">
<div class="pgx-store-flow pgx-store-flow--modes" role="img" aria-label="The CLI publishes immutable policy to the Control Plane over NOTP. The recommended Permguard Data Plane pulls and verifies the signed head, as a sidecar or a remote PDP. A custom Data Plane pulls and verifies the same signed ledger, embedded in a process or at a specialised edge.">
  <article class="pgx-store-flow__source"><small>AUTHOR</small><strong>CLI workspace</strong><span>build · test · push</span></article>
  <div class="pgx-store-flow__link"><i></i><span>NOTP push</span></div>
  <article class="pgx-store-flow__control"><small>CONTROL PLANE</small><strong>Signed policy head</strong><span>immutable ledger</span></article>
  <div class="pgx-store-flow__fanout"><i></i><span>pull + verify</span></div>
  <div class="pgx-store-flow__targets pgx-store-flow__targets--modes">
    <article class="pgx-store-flow__recommended"><small>DEFAULT</small><strong>Permguard Data Plane</strong><span>sidecar · remote PDP</span></article>
    <article class="pgx-store-flow__custom"><small>SPECIAL REQUIREMENTS</small><strong>Custom Data Plane</strong><span>embedded · specialised edge</span></article>
  </div>
</div>
</div>

## Which one?

<div class="pgx-choose" role="table" aria-label="Which Data Plane to run, by need">
  <div class="pgx-choose__head" role="row"><span role="columnheader">You need</span><span role="columnheader">Run</span></div>
  <div class="pgx-choose__row pgx-choose__row--default" role="row"><span role="cell">A PDP beside each workload, inside its failure boundary</span><strong role="cell"><small>Permguard Data Plane</small>sidecar</strong></div>
  <div class="pgx-choose__row pgx-choose__row--default" role="row"><span role="cell">One PDP for many callers, over HTTP or gRPC</span><strong role="cell"><small>Permguard Data Plane</small>remote PDP</strong></div>
  <div class="pgx-choose__row pgx-choose__row--default" role="row"><span role="cell">Signed decision records you do not have to build</span><strong role="cell"><small>Permguard Data Plane</small>either placement</strong></div>
  <div class="pgx-choose__row pgx-choose__row--custom" role="row"><span role="cell">No network hop at all, not even to localhost</span><strong role="cell"><small>Custom Data Plane</small>embedded in your process</strong></div>
  <div class="pgx-choose__row pgx-choose__row--custom" role="row"><span role="cell">Disconnected, safety-critical or platform-specific enforcement</span><strong role="cell"><small>Custom Data Plane</small>specialised edge</strong></div>
  <div class="pgx-choose__row" role="row"><span role="cell">A policy tested before it ships, with no server</span><strong role="cell"><small>Permguard CLI</small><code>permguard test</code></strong></div>
</div>

No custom row fits? Run the Permguard Data Plane.
It mirrors the ledger over NOTP, verifies the signed head and the complete object closure, compiles policy, activates each version atomically and records its decisions as [verifiable evidence](./evidence).

## What stays Permguard's

<div class="pgx-deploy">
  <article><div class="pgx-kicker">Unchanged</div><h3>The ecosystem</h3><p>Publication, the signed ledger, immutable versions, discovery, NOTP transfer and the Control Plane.</p></article>
  <article><div class="pgx-kicker">Yours</div><h3>The runtime</h3><p>The decision runtime and where it runs. Nothing else.</p></article>
</div>

A custom Data Plane consumes the same signed ledgers as the Permguard one, so a policy is written, reviewed and published once, whoever decides with it.

## Six rules to stay trustworthy

<ol class="pgx-vertical-flow" aria-label="Six rules a custom Data Plane follows: discover, mirror, verify, activate, decide, fail closed.">
  <li><b>01</b><div><strong>Discover</strong><span>Start from the Control Plane's server configuration: NOTP routes are discovered, not agreed out of band.</span></div></li>
  <li><b>02</b><div><strong>Mirror over NOTP</strong><span>Negotiate and fetch only the objects you miss. See <a href="./notp">NOTP</a>.</span></div></li>
  <li><b>03</b><div><strong>Verify before use</strong><span>Check the signed head against keys trusted in advance, then every digest, the complete object closure and the manifest.</span></div></li>
  <li><b>04</b><div><strong>Compile and activate atomically</strong><span>Map the declared partitions into your runtime, and serve a version only once it and its checkpoint are durable. See <a href="./policy-lifecycle">Policy Delivery</a>.</span></div></li>
  <li><b>05</b><div><strong>Decide with the same algebra</strong><span>Same commit, same engine build, same answer as every other Data Plane. See <a href="./decision-lifecycle">Decision Path</a>.</span></div></li>
  <li><b>06</b><div><strong>Fail closed</strong><span>Refuse a head that does not verify and an engine range you are outside. Until a new version verifies, decide with the last one that did.</span></div></li>
</ol>

<div class="pgx-resolution"><strong>Rule 05</strong><span>any deny → deny</span><span>else any error → indeterminate</span><span>else any permit → permit</span><span>else → deny by default</span></div>

## Rule 01, in practice

The first thing a Data Plane reads is the pull side of NOTP, from the Control Plane's configuration:

```sh
curl -s http://127.0.0.1:6443/.well-known/server-configuration |
  jq '.notp | {media_type, ref_endpoint, pull_negotiation_endpoint, object_fetch_endpoint}'
```

```json
{
  "media_type": "application/vnd.permguard.notp.v1+cbor",
  "ref_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/refs/{ref}",
  "pull_negotiation_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/pull/negotiate",
  "object_fetch_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/objects/fetch"
}
```

<div class="pgx-note"><strong>Fail closed.</strong><span>An error never becomes a permit, an abstention never an implicit allow, and a version that does not verify is never served.</span></div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./evidence"><span>Previous</span><strong><b aria-hidden="true">←</b> Verifiable Evidence</strong></a>
  <a class="pgx-pager__next" href="./temporal-authorization"><span>Next</span><strong>Temporal Authorization <b aria-hidden="true">→</b></strong></a>
</nav>
