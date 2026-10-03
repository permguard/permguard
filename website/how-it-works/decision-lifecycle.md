---
pageClass: pg-page-concepts
title: Decision Lifecycle
description: How Permguard turns one authorization request into a typed decision.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Decision lifecycle</div>
  <h1>One request. One explicit outcome.</h1>
  <p>The request selects a ledger and profile. The ledger decides which partitions may answer.</p>
</div>

<div class="pgx-decision" role="img" aria-label="A request passes routing, the input gate, compiled partitions, resolution and evidence before a response is returned.">
  <div class="pgx-decision__rail"><i></i></div>
  <article><b>1</b><strong>Route</strong><span>zone · ledger · profile</span></article>
  <article><b>2</b><strong>Input gate</strong><span>shape · type · limits</span></article>
  <article><b>3</b><strong>Evaluate</strong><span>compiled partitions</span></article>
  <article><b>4</b><strong>Resolve</strong><span>typed algebra</span></article>
  <article><b>5</b><strong>Record</strong><span>decision evidence</span></article>
</div>

## The request

```json
{
  "zone": "acme",
  "ledger": "documents",
  "profile": "default",
  "subject": { "type": "User", "id": "alice" },
  "action": { "name": "read" },
  "resource": { "type": "Document", "id": "budget" },
  "context": {}
}
```

The profile selects partitions. The request cannot select a parser or smuggle a new input contract.

## Four internal results

<div class="pgx-algebra">
  <article class="pgx-algebra--permit"><b>P</b><strong>Permit</strong><span>a policy explicitly allowed it</span></article>
  <article class="pgx-algebra--deny"><b>D</b><strong>Deny</strong><span>a policy explicitly refused it</span></article>
  <article><b>A</b><strong>Abstain</strong><span>no rule matched</span></article>
  <article class="pgx-algebra--error"><b>E</b><strong>Indeterminate</strong><span>evaluation could not complete</span></article>
</div>

<div class="pgx-resolution"><strong>Resolution</strong><span>any deny → deny</span><span>else any error → indeterminate</span><span>else any permit → permit</span><span>else → deny by default</span></div>

An error never becomes a permit. An abstention never becomes an implicit allow.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./policy-lifecycle"><span>Previous</span><strong><b aria-hidden="true">←</b> Policy Lifecycle</strong></a>
  <a class="pgx-pager__next" href="./evidence"><span>Next</span><strong>Evidence &amp; Verification <b aria-hidden="true">→</b></strong></a>
</nav>
