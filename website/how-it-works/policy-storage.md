---
pageClass: pg-page-concepts
title: Git-like Policy Storage
description: Local policy files become immutable objects, connected commits and signed published history.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Git-like policy storage</div>
  <h1>Policy has history.</h1>
  <p>Every version has an immutable identity. Every published head is signed. Nothing is silently overwritten.</p>
</div>

## From a policy file to a published commit

Write policy as a normal document. One plan turns it into a validated, immutable version.

<div class="pgx-simple-flow" role="img" aria-label="A policy document enters permguard plan, which extracts and validates it and creates content-addressed objects. Apply creates a commit and pushes it to the Control Plane.">
  <article class="pgx-simple-flow__document"><small>DOCUMENT</small><strong>Policy files</strong><code>permit (principal, action, resource);</code></article>
  <i><span>plan</span><b>→</b></i>
  <article class="pgx-simple-flow__plan"><small>CLI</small><strong>Extract + validate</strong><span>manifest · schema · policies</span></article>
  <i><b>→</b></i>
  <article><small>OBJECTS</small><strong>Blob + tree</strong><code>sha256:7a1…</code></article>
  <i><span>apply</span><b>→</b></i>
  <article class="pgx-simple-flow__commit"><small>COMMIT</small><strong>C3</strong><code>sha256:4b2…</code></article>
  <i><span>push</span><b>→</b></i>
  <article class="pgx-simple-flow__control"><small>CONTROL PLANE</small><strong>refs/main</strong><span>signed head · counter 12</span></article>
</div>

The CLI plans the whole workspace, validates its contract and builds deterministic objects. `apply` connects them in a commit and pushes only the objects the Control Plane is missing.

<div class="pgx-note"><strong>Identity comes from content.</strong><span>The digest is SHA-256 over canonical CBOR. Change one byte and a new object—and therefore a new version—exists.</span></div>

## Pull the same version in two ways

<div class="pgx-pull-paths" role="img" aria-label="A Data Plane pulls a commit, verifies it, loads policy into memory and makes decisions. A CLI workspace pulls the same commit, recreates missing files and lets the author continue editing.">
  <article>
    <div><small>DATA PLANE</small><strong>Run policy</strong></div>
    <ol><li>Pull commit</li><li>Verify closure</li><li>Load in memory</li><li>Make decisions</li></ol>
  </article>
  <article class="pgx-pull-paths__workspace">
    <div><small>CLI WORKSPACE</small><strong>Continue authoring</strong></div>
    <ol><li>Pull commit</li><li>Materialize tree</li><li>Create missing files</li><li>Edit and plan again</li></ol>
  </article>
</div>

The Data Plane does not need editable source state: it verifies, compiles and activates the immutable version. A workspace materializes that same tree back into files; files that do not exist locally are created, then normal authoring resumes. Conflicts are detected before any byte is written.

## Commits preserve the story

<div class="pgx-history-flow" role="img" aria-label="Three immutable parent-linked commits form an ordered history. Each accepted publication advances refs/main and emits a signed head statement with a higher counter.">
  <article><small>COMMIT C1</small><strong>Initial access</strong><code>8f1… · parent ∅</code><span>signed head H10</span></article>
  <i>→</i>
  <article><small>COMMIT C2</small><strong>Add contractors</strong><code>a36… · parent C1</code><span>signed head H11</span></article>
  <i>→</i>
  <article class="pgx-history-flow__current"><small>COMMIT C3</small><strong>Tighten exports</strong><code>4b2… · parent C2</code><span>signed head H12 · refs/main</span></article>
</div>

A commit never changes after creation. Its parent orders it after the previous version. `refs/main` is the movable name: every accepted compare-and-swap advances it atomically and emits a signed head statement with a higher counter. The commit has a content identity; the signed head authenticates its publication.

<div class="pgx-integrity-strip">
  <article><strong>Same digest, different bytes</strong><span>corruption</span></article>
  <article><strong>Lower signed counter</strong><span>rollback</span></article>
  <article><strong>Same counter, different digest</strong><span>equivocation</span></article>
</div>

This is tamper-evident published history: a mirror remembers the accepted counter and ref digest, then refuses a server that presents an older or contradictory state.

## One signed version moves end to end

The workspace creates a commit. The Control Plane publishes it. Every consumer verifies the same signed head before using that commit.

<div class="pgx-distribution-cycle" role="img" aria-label="Workspace A pushes commit C3 and its missing objects to the Control Plane, expecting signed head H11. The Control Plane advances refs/main atomically and emits signed head H12 for C3. Data Planes verify H12 and activate C3; Workspace B materializes C3 and may publish C4 next.">
  <article class="pgx-distribution-cycle__source"><small>WORKSPACE A</small><strong>Create commit C3</strong><span>parent C2 · editable files</span></article>
  <div class="pgx-distribution-cycle__stream"><span>PUSH OBJECT STREAM</span><b>→</b><code>C3 closure · expect H11</code></div>
  <article class="pgx-distribution-cycle__control"><small>CONTROL PLANE</small><strong>Publish C3 atomically</strong><span>refs/main → C3</span><code>signed head H12</code></article>
  <div class="pgx-distribution-cycle__stream"><span>PULL VERIFIED VERSION</span><b>→</b><code>H12 + missing C3 objects</code></div>
  <div class="pgx-distribution-cycle__consumers">
    <article><small>DATA PLANE · EDGE</small><strong>Verify H12</strong><span>activate C3 → decide</span></article>
    <article><small>DATA PLANE · CLUSTER</small><strong>Verify H12</strong><span>activate C3 → decide</span></article>
    <article class="pgx-distribution-cycle__workspace"><small>WORKSPACE B</small><strong>Materialize C3</strong><span>edit → plan → create C4</span></article>
  </div>
  <div class="pgx-distribution-cycle__loop"><b>↺</b><span>Workspace B can push C4 against H12. The Control Plane then publishes H13, and the same verified cycle starts again. Data Planes remain read-only consumers.</span></div>
</div>

The signature travels in the head statement, not by changing the immutable commit. Any number of Data Planes can verify H12 and activate the identical C3 closure. A workspace instead materializes C3 as files and may extend it; compare-and-swap prevents that workspace from overwriting a newer published head.

## Push only what is missing

<ol class="pgx-vertical-flow">
  <li><b>01</b><div><strong>Negotiate</strong><span>Send the proposed head, expected ref and closure summary.</span></div></li>
  <li><b>02</b><div><strong>Upload</strong><span>The Control Plane asks only for digests it does not already hold.</span></div></li>
  <li><b>03</b><div><strong>Verify</strong><span>Every object is decoded, rehashed and checked as a complete policy closure.</span></div></li>
  <li><b>04</b><div><strong>Commit atomically</strong><span>The ref advances once and the Control Plane produces its signed head.</span></div></li>
</ol>

<div class="pgx-note"><strong>Git-like, not Git.</strong><span>The object graph, immutable commits and refs are deliberate Git-like semantics. Permguard uses its own canonical policy model and NOTP transfer protocol.</span></div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./architecture"><span>Previous</span><strong><b aria-hidden="true">←</b> Server, Host &amp; Planes</strong></a>
  <a class="pgx-pager__next" href="./bring-your-own-data-plane"><span>Next</span><strong>Bring Your Own Data Plane <b aria-hidden="true">→</b></strong></a>
</nav>
