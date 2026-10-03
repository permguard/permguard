---
pageClass: pg-page-concepts
title: Data Plane
description: Evaluate verified policy embedded, as a sidecar, remotely or at your own edge.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Data Plane · :7443</div>
  <h1>Decide where the action happens.</h1>
  <p>A verified policy version becomes a fast, explicit authorization answer.</p>
</div>

<div class="pgx-discovery pgx-discovery--decision" role="img" aria-label="A Policy Enforcement Point asks the Permguard Data Plane, acting as Policy Decision Point, and then enforces permit, deny or error.">
  <article><small>PEP</small><strong>Ask</strong><span>application · gateway · agent</span></article><i>→</i>
  <article class="pgx-discovery__accent"><small>PDP · DATA PLANE</small><strong>Evaluate</strong><span>verified policy version</span></article><i>→</i>
  <article><small>PEP</small><strong>Enforce</strong><span>permit · deny · error</span></article>
</div>

A Policy Enforcement Point (PEP) guards an action. The Policy Decision Point (PDP) answers its authorization question. The PEP—not the PDP—applies the result.

## Place it where it fits

<div class="pgx-byo-targets">
  <article><small>SUPPORTED DEFAULT</small><strong>Sidecar</strong><span>Local network boundary, independent lifecycle.</span></article>
  <article><small>SUPPORTED DEFAULT</small><strong>Remote service</strong><span>Shared PDP behind a versioned interface.</span></article>
  <article><small>CUSTOM NEED</small><strong>Embedded</strong><span>No network hop inside your component.</span></article>
  <article><small>CUSTOM NEED</small><strong>Specialised edge</strong><span>Your runtime, Permguard's signed policy ecosystem.</span></article>
</div>

The supported Permguard Data Plane is the secure default for sidecar and remote deployments. Build a custom Data Plane when an embedded or specialised edge runtime is a real requirement; it can still consume signed ledgers, use NOTP for policy transfer and participate in the same Control Plane ecosystem.

The current general evaluation profile is <code>permguard.api.pdp.native.v1</code>. Profiles are explicit, versioned questions: future interfaces can add different request shapes without silently changing this contract.

See [Bring Your Own Data Plane](./how-it-works/bring-your-own-data-plane) for the boundary and [Decision Lifecycle](./how-it-works/decision-lifecycle) for one request end to end.
