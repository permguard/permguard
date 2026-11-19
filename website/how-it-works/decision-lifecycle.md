---
pageClass: pg-page-concepts
title: Decision Path
description: "One request, one answer: what happens between your application's question and the answer it enforces."
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Decision path</div>
  <h1>One question. One answer, on record.</h1>
  <p>Your application asks, Permguard decides and records, and the answer names the policy that decided.</p>
</div>

## The idea

Before it acts, your application asks one question: may this [subject](./glossary#subject) do this [action](./glossary#action) on this [resource](./glossary#resource), given this [context](./glossary#context)?
The [Data Plane](./glossary#data-plane), the [PDP](./glossary#pdp), answers with the policy it already holds, without calling the Control Plane.
The [decision](./glossary#decision) is recorded, and the answer comes back naming the policy that decided.

<div class="pgx-decision" role="img" aria-label="One request in four steps. The application asks with a subject, an action, a resource and a context. The Data Plane decides with the policy it already holds. The decision is recorded, signed and chained. The answer comes back, permit or deny, naming the policy that decided.">
  <div class="pgx-decision__rail"><i></i></div>
  <article><b>1</b><strong>Ask</strong><span>who · does what · on what · context</span></article>
  <article><b>2</b><strong>Decide</strong><span>with the policy already here</span></article>
  <article><b>3</b><strong>Record</strong><span>signed · chained</span></article>
  <article><b>4</b><strong>Answer</strong><span>naming the policy</span></article>
</div>

Nothing is permitted unless a policy permits it.
In the shipped configurations the answer leaves only once its record is durable.

## In practice

Your application, the [PEP](./glossary#pep), asks through a Permguard SDK:

<!--@include: ../snippets/sdk-check.md-->

The answer is always one of three.

<div class="pgx-algebra pgx-outcomes">
  <article class="pgx-algebra--permit"><b>P</b><strong>Permit</strong><span>a policy allowed it: go ahead</span></article>
  <article class="pgx-algebra--deny"><b>D</b><strong>Deny</strong><span>no policy permits it: stop</span></article>
  <article class="pgx-algebra--error"><b>E</b><strong>Error</strong><span>no decision was made: treat it as a no</span></article>
</div>

An error is not a deny: it means no decision was made, so your code must treat it as a no.
These are real answers of the Data Plane, abridged:

::: code-group

```json [Permit]
{
  "decision": true,
  "context": {
    "id": "01a1f111-df65-77cf-b171-3facea0cbc27",
    "reason_admin": {
      "code": "200",
      "message": "permitted by 92efe24a-8620-8bcd-b026-a19c1f440c45"
    },
    "policies": ["92efe24a-8620-8bcd-b026-a19c1f440c45"],
    "evidence": { "mode": "required", "status": "durable" }
  }
}
```

```json [Deny]
{
  "decision": false,
  "context": {
    "id": "01a1f111-df7c-737b-82ef-9208ea5e1685",
    "reason_admin": {
      "code": "403",
      "message": "no policy permits this request"
    },
    "reason_user": {
      "code": "403",
      "message": "insufficient privileges. Contact your administrator"
    },
    "evidence": { "mode": "required", "status": "durable" }
  }
}
```

```json [Error]
{
  "class": "not_found",
  "code": "ledger_not_served",
  "message": "this plane does not serve `quickstart/policies`"
}
```

:::

`context.id` is the decision id: it finds the record of this decision later.

## Why it matters

<div class="pgx-principles">
  <article><span>Developers</span><h3>Ask, then obey.</h3><p>The rule lives in a policy, not in your code: you ask, and anything but a permit is a no.</p></article>
  <article><span>Platform & IT</span><h3>Decided close to the workload.</h3><p>The Data Plane already holds the policy, so a decision never waits for the Control Plane.</p></article>
  <article><span>Security & CISO</span><h3>Every answer has a reason.</h3><p>Nothing is permitted unless a policy permits it, and every answer names the policy and is on record.</p></article>
</div>

## Go deeper

<div class="pgx-link-grid">
  <a href="./policy-lifecycle"><strong>Policy Delivery</strong><span>how the policy got there</span></a>
  <a href="./evidence"><strong>Verifiable Evidence</strong><span>what the record proves</span></a>
  <a href="../data-plane"><strong>Data Plane</strong><span>where decisions are made</span></a>
  <a href="./glossary"><strong>Glossary</strong><span>every term, in one line</span></a>
</div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./policy-lifecycle"><span>Previous</span><strong><b aria-hidden="true">←</b> Policy Delivery</strong></a>
  <a class="pgx-pager__next" href="./evidence"><span>Next</span><strong>Verifiable Evidence <b aria-hidden="true">→</b></strong></a>
</nav>
