---
pageClass: pg-page-concepts
title: Command Line
description: Author, validate, publish and query Permguard policy from one CLI.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Command Line</div>
  <h1>Policy work, end to end.</h1>
  <p>One CLI for local authoring, immutable publication and runtime inspection.</p>
</div>

<div class="pgx-discovery" role="img" aria-label="The Permguard CLI authors and validates local files, publishes signed commits to the Control Plane, and asks the Data Plane for decisions.">
  <article><small>LOCAL</small><strong>Author + validate</strong><span>readable policy files</span></article><i>→</i>
  <article class="pgx-discovery__accent"><small>CONTROL PLANE</small><strong>Plan + apply</strong><span>immutable signed version</span></article><i>→</i>
  <article><small>DATA PLANE</small><strong>Check + inspect</strong><span>decision and evidence</span></article>
</div>

## The six commands to learn first

<div class="pgx-image-grid pgx-image-grid--commands">
  <article><small>CREATE</small><strong><code>init</code></strong><span>Start a language-aware workspace.</span></article>
  <article><small>PROVE LOCALLY</small><strong><code>validate</code> · <code>test</code></strong><span>Catch invalid policy before a server sees it.</span></article>
  <article><small>REVIEW</small><strong><code>plan</code></strong><span>See the exact object and ref changes.</span></article>
  <article><small>PUBLISH</small><strong><code>apply</code></strong><span>Create and push an immutable commit.</span></article>
  <article><small>DECIDE</small><strong><code>check</code></strong><span>Ask the selected PDP interface.</span></article>
  <article><small>UNDERSTAND</small><strong><code>inspect</code></strong><span>Discover deployed planes and capabilities.</span></article>
</div>

The CLI keeps editable files local and transfers content-addressed objects over NOTP when publishing or pulling. A workspace can continue from a remote head without rewriting history.

Start with [Install](./how-it-works/install), then run the complete [Getting Started](./how-it-works/getting-started) flow.
