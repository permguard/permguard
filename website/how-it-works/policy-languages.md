---
pageClass: pg-page-concepts
title: Policy Languages
description: Cedar, Rego and Dogwood share one bounded decision contract.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Policy languages</div>
  <h1>Different languages. One safety contract.</h1>
  <p>Every runtime is built in, bounded, deterministic and unable to turn an error into a permit.</p>
</div>

<div class="pgx-languages">
  <article>
    <div class="pgx-language-mark">C</div>
    <div><span>Stable</span><h2>Cedar</h2><p>Typed authorization over principals, actions, resources and entities.</p><strong>Best for · application permissions</strong></div>
  </article>
  <article>
    <div class="pgx-language-mark">R</div>
    <div><span>Stable</span><h2>Rego</h2><p>Structured rules over JSON-shaped requests and supporting data.</p><strong>Best for · contextual guardrails</strong></div>
  </article>
  <article class="pgx-languages__experimental">
    <div class="pgx-language-mark">D</div>
    <div><span>Experimental</span><h2>Dogwood</h2><p>Temporal policy over occurrences, history windows and frontiers.</p><strong>Best for · decisions from history</strong></div>
  </article>
</div>

## One path into the Data Plane

<div class="pgx-language-flow" role="img" aria-label="Cedar, Rego and Dogwood pass through the same manifest gate, compilation limits and typed decision algebra.">
  <div><span>Cedar</span><span>Rego</span><span>Dogwood</span></div>
  <i>↓</i><strong>Manifest contract</strong><i>↓</i><strong>Bounded compilation</strong><i>↓</i><strong>P · D · A · E</strong>
</div>

Every language must provide:

- immutable descriptors and exact engine identity;
- strict artifact and input ownership;
- bounded parse, compile and evaluation work;
- stable policy attribution;
- no ambient filesystem, network, process, clock or randomness.

## Choose by question

| If the question is… | Start with |
| --- | --- |
| “May this user perform this action on this resource?” | Cedar |
| “Does this structured request satisfy operational rules?” | Rego |
| “May this happen after those verified events?” | Dogwood |

One profile may combine partitions. A deny still wins across the whole profile.

<nav class="pgx-pager pgx-pager--previous-only" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./temporal-authorization"><span>Previous</span><strong><b aria-hidden="true">←</b> Temporal Authorization</strong></a>
</nav>
