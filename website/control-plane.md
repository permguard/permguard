---
pageClass: pg-page-concepts
title: Control Plane
description: Publish, verify and distribute immutable policy history.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Control Plane · :6443</div>
  <h1>Policy has a history.</h1>
  <p>The Control Plane stores immutable objects, advances signed heads and distributes exact versions.</p>
</div>

<div class="pgx-store-flow" role="img" aria-label="A workspace publishes a signed policy commit to the authoritative Control Plane. Data Planes and other workspaces pull and verify that exact version.">
  <article><small>WORKSPACE</small><strong>Plan + commit</strong><span>editable policy files</span></article>
  <div class="pgx-store-flow__link"><i></i><span>NOTP push</span></div>
  <article class="pgx-store-flow__control"><small>CONTROL PLANE</small><strong>Signed ledger head</strong><span>immutable object graph</span></article>
  <div class="pgx-store-flow__fanout"><i></i><span>NOTP pull</span></div>
  <div class="pgx-store-flow__targets"><article><small>DATA PLANE</small><strong>Verify + activate</strong></article><article><small>WORKSPACE</small><strong>Pull + continue</strong></article></div>
</div>

## What it owns

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card"><span>Ledgers</span><h3>Immutable versions</h3><p>Commits point to canonical trees, manifests, parents and content-addressed policy objects.</p></article>
  <article class="pgx-card pgx-card--accent"><span>Signed heads</span><h3>One accepted state</h3><p>A monotonic, signed ref selects the current commit without rewriting previous versions.</p></article>
  <article class="pgx-card"><span>Distribution</span><h3>Only missing objects</h3><p>NOTP negotiates and transfers the content the receiver does not already hold.</p></article>
</div>

The Control Plane does not make authorization decisions. It publishes the exact policy version that a Data Plane verifies, compiles and evaluates.

Read [Git-like Policy Storage](./how-it-works/policy-storage) for the object model and [Policy Lifecycle](./how-it-works/policy-lifecycle) for the complete flow.
