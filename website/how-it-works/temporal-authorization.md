---
pageClass: pg-page-concepts
title: Temporal Authorization
description: Make authorization decisions from verified event history.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Temporal authorization · experimental</div>
  <h1>Decide from what happened.</h1>
  <p>Dogwood turns verified events into policy input, so a later action can depend on earlier facts.</p>
</div>

<div class="pgx-timeline" role="img" aria-label="A login request and successful login occurrence create history that allows a later document read inside its policy window.">
  <div class="pgx-timeline__line"><i></i></div>
  <article><b>1</b><strong>login.requested</strong><span>local sequence 41</span></article>
  <article><b>2</b><strong>login.succeeded</strong><span>local sequence 42</span></article>
  <article class="pgx-timeline__decision"><b>✓</b><strong>document.read</strong><span>history satisfies policy</span></article>
</div>

## Events become authorization input

An event is a canonical occurrence: what happened, who produced it and where it sits in that producer's durable sequence. Permguard appends it before using it to change authorization history.

<div class="pgx-event-stream" role="img" aria-label="Producers append occurrences to a durable event stream. Dogwood applies the verified history and evaluates a later request against it.">
  <article><small>PRODUCERS</small><strong>Occurrences</strong><span>login · approval · risk</span></article>
  <div class="pgx-event-stream__rail"><i></i><b>append</b></div>
  <article class="pgx-event-stream__journal"><small>DURABLE STREAM</small><strong>41 · 42 · 43 · 44</strong><span>canonical local order</span></article>
  <div class="pgx-event-stream__rail"><i></i><b>apply</b></div>
  <article class="pgx-event-stream__decision"><small>DOGWOOD</small><strong>Evaluate now</strong><span>request + verified history</span></article>
</div>

This answers questions a stateless rule cannot: “Did login succeed before this read?”, “Was this deployment approved?” or “Was risk raised after the credential was issued?”

## The temporal contract

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card"><span>Occurrence</span><h3>Something happened</h3><p>Canonical event data with an origin and local order.</p></article>
  <article class="pgx-card"><span>Frontier</span><h3>What is known</h3><p>A vector names the exact verified history used by the decision.</p></article>
  <article class="pgx-card pgx-card--accent"><span>Outcome</span><h3>What follows</h3><p>The answer states its history frontier and any gap or degraded state.</p></article>
</div>

## No fictional total order

Each producer owns its local sequence. Imported history advances a vector frontier. A gap stays a gap; Permguard never hides it behind wall-clock ordering.

<div class="pgx-frontier"><span>agent-a · 42</span><span>agent-b · 17</span><span>gateway · 103</span><strong>exact frontier</strong></div>

`occurred_at` is a source claim. `accepted_at` is the Host clock. The stream position is the durable order. A decision records the exact per-origin frontier it used rather than inventing one global timeline.

## Read history as a stream

Consumers page through immutable records with an opaque cursor:

```sh
curl -s \
  'http://127.0.0.1:6443/v1/zones/acme/ledgers/sessions/events/v1alpha1/records?limit_records=100' \
  | jq
```

<div class="pgx-stream-reader" aria-label="A reader requests a page from a cursor, receives records and continues from the returned next cursor until more is false or its fixed boundary is reached.">
  <article><small>REQUEST</small><strong>from</strong><span>opaque cursor</span></article>
  <i>→</i>
  <article class="pgx-stream-reader__page"><small>BLOCK</small><strong>records[]</strong><span>proof · coverage</span></article>
  <i>→</i>
  <article><small>CONTINUE</small><strong>next</strong><span>while more = true</span></article>
</div>

Pin `until` when a reader needs a fixed snapshot. `high_watermark` says how far the stream has advanced. If retention removed the requested offset, the API returns an explicit `offset_expired` gap; it never silently restarts from newer history.

## Run the experimental path

```sh
task run:experimental
```

The example in `examples/dogwood-session-access` shows login history controlling later document access.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./evidence"><span>Previous</span><strong><b aria-hidden="true">←</b> Evidence &amp; Verification</strong></a>
  <a class="pgx-pager__next" href="./policy-languages"><span>Next</span><strong>Policy Languages <b aria-hidden="true">→</b></strong></a>
</nav>
