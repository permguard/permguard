---
pageClass: pg-page-concepts
title: Evidence and Verification
description: How a decision remains attributable and independently verifiable.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Evidence &amp; verification</div>
  <h1>An answer is not enough.</h1>
  <p>A decision identity joins the response to a verifiable record and its exact policy version.</p>
</div>

<div class="pgx-evidence" role="img" aria-label="A decision response and its evidence share one identity. Evidence records form a signed hash chain with retained checkpoints.">
  <div class="pgx-evidence__answer"><small>RESPONSE</small><strong>decision_id</strong><span>permit · commit · reasons</span></div>
  <div class="pgx-evidence__join"><i></i><b>=</b></div>
  <div class="pgx-evidence__answer pgx-evidence__answer--record"><small>EVIDENCE</small><strong>decision_id</strong><span>canonical · signed · chained</span></div>
  <div class="pgx-evidence__chain"><i></i><i></i><i></i><i></i></div>
</div>

## What verification proves

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card"><span>01</span><h3>Integrity</h3><p>The canonical record bytes still match their digest and signed envelope.</p></article>
  <article class="pgx-card"><span>02</span><h3>Traceability</h3><p>Sequence and previous digest make gaps and forks in the producer history visible.</p></article>
  <article class="pgx-card pgx-card--accent"><span>03</span><h3>Attribution</h3><p>The signer, ledger commit and determining policies remain explicit.</p></article>
</div>

## Traceability is not authority continuity

<div class="pgx-deploy">
  <article><div class="pgx-kicker">Evidence · available now</div><h3>Trace the decision</h3><p>Verify bytes, ordering, signer, policy version and determining policies after the decision.</p></article>
  <article><div class="pgx-kicker">Trust Plane · in development</div><h3>Continue authority</h3><p>Authority continuity and Trust Anchor evaluation belong to a separate contract, reserved on port <code>8443</code> but not served today.</p></article>
</div>

Signed evidence supports cryptographic attribution and non-repudiation claims, subject to key custody and compromise evidence. It does not prove human intent, establish a legal conclusion by itself or decide whether authority may continue into another execution.

See the [Trust Plane status and planned boundary](../trust-plane).

## Read it back

```sh
permguard decisions list --zone acme --ledger main-ledger
permguard decisions tail --zone acme --ledger main-ledger --follow
permguard decisions get <decision-id> --zone acme --ledger main-ledger
```

Verify the chain and signatures against the Data Plane keys:

```sh
permguard decisions list \
  --zone acme \
  --ledger main-ledger \
  --verify \
  --keys data-plane-keys.json
```

<div class="pgx-note"><strong>No timestamp guessing.</strong><span>The response and record carry the same decision identity.</span></div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./decision-lifecycle"><span>Previous</span><strong><b aria-hidden="true">←</b> Decision Lifecycle</strong></a>
  <a class="pgx-pager__next" href="./temporal-authorization"><span>Next</span><strong>Temporal Authorization <b aria-hidden="true">→</b></strong></a>
</nav>
