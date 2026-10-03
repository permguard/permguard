---
pageClass: pg-page-concepts
title: Bring Your Own Data Plane
description: Connect Permguard policy distribution to an enforcement point inside your infrastructure.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Bring your own Data Plane</div>
  <h1>One ecosystem. Your boundary.</h1>
  <p>Use the Permguard Data Plane by default. Build your own only when the decision must live inside your runtime or at a specialised edge.</p>
</div>

<div class="pgx-store-flow pgx-store-flow--modes" role="img" aria-label="The CLI publishes immutable policy to the Control Plane. The recommended Permguard Data Plane pulls and verifies it for sidecar or remote deployment. A custom Data Plane is available for embedded or specialised edge requirements.">
  <article class="pgx-store-flow__source"><small>AUTHOR</small><strong>CLI workspace</strong><span>build · test · push</span></article>
  <div class="pgx-store-flow__link"><i></i><span>NOTP push</span></div>
  <article class="pgx-store-flow__control"><small>CONTROL PLANE</small><strong>Signed policy head</strong><span>immutable ledger</span></article>
  <div class="pgx-store-flow__fanout"><i></i><span>pull + verify</span></div>
  <div class="pgx-store-flow__targets pgx-store-flow__targets--modes">
    <article class="pgx-store-flow__recommended"><small>RECOMMENDED</small><strong>Permguard Data Plane</strong><span>sidecar · remote PDP</span></article>
    <article class="pgx-store-flow__custom"><small>SPECIAL REQUIREMENTS</small><strong>Custom Data Plane</strong><span>embedded · critical edge</span></article>
  </div>
</div>

## Start with the Permguard Data Plane

The Permguard Data Plane is the secure, supported default. It mirrors the ledger, verifies the signed head and complete object closure, compiles policy and activates each version atomically. Run it beside a workload as a sidecar or expose it as a remote PDP service.

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card"><span>Secure by default</span><h3>Verify every version</h3><p>Signed-head freshness, digests, closure and manifest are checked before activation.</p></article>
  <article class="pgx-card pgx-card--accent"><span>Local placement</span><h3>Run it as a sidecar</h3><p>Keep the supported runtime beside the workload and inside the same failure boundary.</p></article>
  <article class="pgx-card"><span>Shared placement</span><h3>Run it remotely</h3><p>Serve the versioned PDP interface centrally when a network decision path fits.</p></article>
</div>

## Build your own only when placement demands it

<div class="pgx-deploy">
  <article><div class="pgx-kicker">Embedded</div><h3>Inside your component</h3><p>Use the engine libraries and decide in process when even a local network hop is unacceptable.</p></article>
  <article><div class="pgx-kicker">Specialised edge</div><h3>Inside your infrastructure</h3><p>Implement a custom runtime for disconnected, safety-critical or platform-specific enforcement.</p></article>
</div>

This is an extension path, not a warning against the Permguard Data Plane. A custom implementation remains part of the same ecosystem by consuming the signed ledger and preserving the verification and activation guarantees.

## If you build it, preserve five guarantees

<ol class="pgx-vertical-flow">
  <li><b>01</b><div><strong>Discover</strong><span>Start from the Control Plane server configuration.</span></div></li>
  <li><b>02</b><div><strong>Mirror</strong><span>Use NOTP to negotiate and transfer only the missing policy objects.</span></div></li>
  <li><b>03</b><div><strong>Verify</strong><span>Check authority, signed-head freshness, digests, closure and manifest.</span></div></li>
  <li><b>04</b><div><strong>Compile</strong><span>Map declared policy partitions into your supported runtime.</span></div></li>
  <li><b>05</b><div><strong>Activate atomically</strong><span>Serve only after the verified version and checkpoint are durable.</span></div></li>
</ol>

<div class="pgx-note"><strong>Freedom without fragmentation</strong><span>Keep Permguard publication, immutable versions, discovery and efficient transfer. Replace only the decision runtime and placement that your requirements make different.</span></div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./policy-storage"><span>Previous</span><strong><b aria-hidden="true">←</b> Git-like Policy Storage</strong></a>
  <a class="pgx-pager__next" href="./policy-lifecycle"><span>Next</span><strong>Policy Lifecycle <b aria-hidden="true">→</b></strong></a>
</nav>
