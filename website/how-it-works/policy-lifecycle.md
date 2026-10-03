---
pageClass: pg-page-concepts
title: Policy Lifecycle
description: How policy becomes an immutable, signed and verified version.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Policy lifecycle</div>
  <h1>Write once. Verify at every boundary.</h1>
  <p>Policy travels as immutable, content-addressed objects under a signed published head.</p>
</div>

<ol class="pgx-vertical-flow" aria-label="Author, validate, commit, publish, mirror and compile a policy.">
  <li><b>01</b><div><strong>Author</strong><span>Cedar, Rego or Dogwood in a workspace.</span></div></li>
  <li><b>02</b><div><strong>Validate</strong><span>Manifest, types, identities and tests close locally.</span></div></li>
  <li><b>03</b><div><strong>Commit</strong><span>Canonical bytes become content-addressed objects.</span></div></li>
  <li><b>04</b><div><strong>Publish</strong><span>The Control Plane accepts the closure and advances a signed head.</span></div></li>
  <li><b>05</b><div><strong>Mirror</strong><span>The Data Plane fetches only what is missing and verifies before use.</span></div></li>
  <li><b>06</b><div><strong>Compile</strong><span>Each partition is compiled once and cached by immutable identity.</span></div></li>
</ol>

## Four commands before publish

```sh
permguard validate
permguard test
permguard plan
permguard apply -m "explain the change"
```

<div class="pgx-equation"><span>same commit</span><b>+</b><span>same engine build</span><b>=</b><strong>same meaning</strong></div>

## The ledger is not a folder

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card"><span>Objects</span><h3>Content addressed</h3><p>Change one byte, get a different digest.</p></article>
  <article class="pgx-card"><span>Manifest</span><h3>Meaning is explicit</h3><p>Runtimes, partitions, profiles and input contracts are signed together.</p></article>
  <article class="pgx-card pgx-card--accent"><span>Head</span><h3>Published state advances</h3><p>The signed head names exactly one accepted version.</p></article>
</div>

The Data Plane activates only versions whose signed head and complete object closure verify.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./bring-your-own-data-plane"><span>Previous</span><strong><b aria-hidden="true">←</b> Bring Your Own Data Plane</strong></a>
  <a class="pgx-pager__next" href="./decision-lifecycle"><span>Next</span><strong>Decision Lifecycle <b aria-hidden="true">→</b></strong></a>
</nav>
