---
pageClass: pg-page-concepts
title: Trust Plane
description: The in-development plane for authority continuity and Trust Anchors across execution chains.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Trust Plane · in development</div>
  <h1>Authority that survives the next hop.</h1>
  <p>A dedicated plane for Trust Anchors, authority hand-off and continuity across execution chains.</p>
</div>

<div class="pgx-note pgx-note--status"><strong>Architectural contract, not a live API.</strong><span>Port <code>8443</code> is reserved. The current runtime does not serve or advertise the Trust Plane.</span></div>

<div class="pgx-trust-flow" role="img" aria-label="An execution carries bounded authority to a Trust Anchor. The Trust Anchor validates the continuation before the next execution receives authority that never expands.">
  <article><small>CURRENT EXECUTION</small><strong>Bounded authority</strong><span>what this execution may do</span></article>
  <div><span>present proof</span><b>→</b></div>
  <article class="pgx-trust-flow__anchor"><small>TRUST ANCHOR</small><strong>Validate continuation</strong><span>policy · relationship · evidence</span></article>
  <div><span>continue, never expand</span><b>→</b></div>
  <article><small>NEXT EXECUTION</small><strong>Derived authority</strong><span>same or narrower boundary</span></article>
</div>

## Authorization and continuity are different

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card"><span>Data Plane · available</span><h3>May this action happen?</h3><p>The PDP evaluates policy for one authorization question.</p></article>
  <article class="pgx-card"><span>Evidence · available</span><h3>What produced the answer?</h3><p>Signed records preserve integrity, ordering, attribution and the exact policy version.</p></article>
  <article class="pgx-card pgx-card--accent"><span>Trust Plane · in development</span><h3>May authority continue?</h3><p>A Trust Anchor validates the hand-off into the next execution.</p></article>
</div>

Traceability can prove where a decision came from. It does not grant the next execution authority. Authority continuity is a separate protocol and policy question.

## Where it fits

<div class="pgx-server" role="img" aria-label="A Permguard Server Host provides shared identity, authorization, keys, audit, membership and streams to an in-development Trust Plane on reserved port 8443.">
  <div class="pgx-server__label"><strong>Permguard Server</strong><span>one Host · zero or more planes</span></div>
  <div class="pgx-server__host">
    <div><span>HOST</span><strong>Identity · Authorization · Keys · Audit · Membership · Streams</strong></div>
    <small>shared capabilities</small>
  </div>
  <div class="pgx-server__bus" aria-hidden="true"></div>
  <div class="pgx-server__planes pgx-server__planes--single">
    <article class="pgx-server__optional"><span>:8443</span><strong>Trust Plane</strong><small>in development · not served today</small></article>
  </div>
</div>

Like every plane, Trust will have its own well-known plane configuration and versioned interfaces. The Host will advertise it only when the deployed Server actually contains it. Reserving <code>8443</code> now keeps all-in-one and split-by-plane topologies stable.

## Planned contract

<div class="pgx-vertical-flow">
  <li><b>01</b><div><strong>Discover</strong><span>The Host advertises a Trust Plane configuration only when it is enabled.</span></div></li>
  <li><b>02</b><div><strong>Describe</strong><span>The plane names its Trust Anchor interfaces, keys and capabilities.</span></div></li>
  <li><b>03</b><div><strong>Present</strong><span>An execution presents bounded authority and the proof required by the selected profile.</span></div></li>
  <li><b>04</b><div><strong>Evaluate</strong><span>The Trust Anchor applies the explicit continuation contract.</span></div></li>
  <li><b>05</b><div><strong>Continue</strong><span>The next execution receives authority that is equal or narrower, never silently broader.</span></div></li>
</div>

The exact request schemas, outcomes, threat model and evidence contract are intentionally not documented as usable API yet: they will become normative only with the implementation.

## What exists today

Permguard already has supporting foundations—Host-owned identity and keys, signed policy versions, decision evidence, audit streams and TLS/mTLS configuration. They make future Trust Plane integration coherent, but they are not a substitute for its missing runtime and interfaces.

## What remains in development

- Trust Anchor evaluation profiles and their versioned questions
- authority hand-off and continuation proofs
- Trust Plane discovery and well-known configuration
- lifecycle, readiness, conformance and interoperability tests

The protocol direction is developed alongside the [PIC Protocol](https://www.pic-protocol.org/). Until these contracts ship, treat this page as the reserved architecture and status boundary.

<nav class="pgx-pager pgx-pager--previous-only" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./how-it-works/architecture"><span>Previous</span><strong><b aria-hidden="true">←</b> Server, Host &amp; Planes</strong></a>
</nav>
