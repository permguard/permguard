---
pageClass: pg-page-concepts
title: Zones & Ledgers
description: The zone is the security boundary; a zone has one or more ledgers, and a ledger belongs to exactly one zone.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Zones &amp; ledgers</div>
  <h1>The zone is the boundary.</h1>
  <p>A zone has one or more ledgers, a ledger belongs to exactly one zone, and every request names both.</p>
</div>

## The idea

A [zone](./glossary#zone) is the security boundary: everything inside it is governed together, and nothing crosses it unless it is allowed to.
A zone has one or more [ledgers](./glossary#ledger), and a ledger is the versioned history of a set of policies.
A ledger belongs to exactly one zone, for life: nothing moves it to another.

<figure class="pgx-zl" role="img" aria-label="Two zones, acme and billing, each a security boundary. Zone acme has the ledgers main-ledger and sessions; zone billing has the ledger invoices. A request naming zone acme and ledger main-ledger reaches that one ledger.">
  <svg class="pgx-zl__wide" viewBox="0 0 760 320" aria-hidden="true" focusable="false">
    <rect class="pgx-zl__request" x="8" y="96" width="180" height="124" rx="14"/>
    <text class="pgx-zl__k" x="24" y="124">REQUEST</text>
    <text class="pgx-zl__c" x="24" y="154"><tspan>zone</tspan>   acme</text>
    <text class="pgx-zl__c" x="24" y="178"><tspan>ledger</tspan> main-ledger</text>
    <text class="pgx-zl__m" x="24" y="204">+ who · what · on what</text>
    <rect class="pgx-zl__zone" x="220" y="20" width="300" height="280" rx="18"/>
    <text class="pgx-zl__k" x="240" y="50">ZONE · ACME</text>
    <text class="pgx-zl__m" x="240" y="70">the security boundary</text>
    <rect class="pgx-zl__ledger pgx-zl__ledger--target" x="240" y="92" width="260" height="76" rx="12"/>
    <text class="pgx-zl__s" x="256" y="124">main-ledger</text>
    <text class="pgx-zl__m" x="256" y="148">policies · history · signed version</text>
    <rect class="pgx-zl__ledger" x="240" y="184" width="260" height="76" rx="12"/>
    <text class="pgx-zl__s" x="256" y="216">sessions</text>
    <text class="pgx-zl__m" x="256" y="240">its own history</text>
    <rect class="pgx-zl__zone pgx-zl__zone--other" x="540" y="20" width="212" height="280" rx="18"/>
    <text class="pgx-zl__k" x="558" y="50">ZONE · BILLING</text>
    <text class="pgx-zl__m" x="558" y="70">another boundary</text>
    <rect class="pgx-zl__ledger" x="558" y="92" width="178" height="76" rx="12"/>
    <text class="pgx-zl__s" x="574" y="124">invoices</text>
    <text class="pgx-zl__m" x="574" y="148">outside acme's grants</text>
    <path class="pgx-zl__flow" d="M188 158 H204 V130 H232"/>
    <path class="pgx-zl__head" d="M232 124 L240 130 L232 136 Z"/>
  </svg>
  <svg class="pgx-zl__compact" viewBox="0 0 360 572" aria-hidden="true" focusable="false">
    <rect class="pgx-zl__request" x="16" y="8" width="328" height="112" rx="14"/>
    <text class="pgx-zl__k" x="32" y="34">REQUEST</text>
    <text class="pgx-zl__c" x="32" y="62"><tspan>zone</tspan>   acme</text>
    <text class="pgx-zl__c" x="32" y="86"><tspan>ledger</tspan> main-ledger</text>
    <text class="pgx-zl__m" x="32" y="108">+ who · what · on what</text>
    <rect class="pgx-zl__zone" x="16" y="144" width="328" height="236" rx="18"/>
    <text class="pgx-zl__k" x="32" y="172">ZONE · ACME</text>
    <path class="pgx-zl__flow" d="M180 124 V186"/>
    <path class="pgx-zl__head" d="M174 188 L180 196 L186 188 Z"/>
    <rect class="pgx-zl__ledger pgx-zl__ledger--target" x="32" y="198" width="296" height="76" rx="12"/>
    <text class="pgx-zl__s" x="48" y="230">main-ledger</text>
    <text class="pgx-zl__m" x="48" y="254">policies · history · signed version</text>
    <rect class="pgx-zl__ledger" x="32" y="288" width="296" height="76" rx="12"/>
    <text class="pgx-zl__s" x="48" y="320">sessions</text>
    <text class="pgx-zl__m" x="48" y="344">its own history</text>
    <rect class="pgx-zl__zone pgx-zl__zone--other" x="16" y="404" width="328" height="156" rx="18"/>
    <text class="pgx-zl__k" x="32" y="432">ZONE · BILLING</text>
    <rect class="pgx-zl__ledger" x="32" y="460" width="296" height="76" rx="12"/>
    <text class="pgx-zl__s" x="48" y="492">invoices</text>
    <text class="pgx-zl__m" x="48" y="516">outside acme's grants</text>
  </svg>
</figure>

Inside a ledger there is one more level: the partition, where the policies of one language live.

| Level     | What it is                                 | What it holds                                            |
| --------- | ------------------------------------------ | -------------------------------------------------------- |
| Zone      | the security boundary                      | one or more ledgers                                      |
| Ledger    | the versioned history of a set of policies | commits, each with its manifest                          |
| Partition | the policies of exactly one language       | policy files and, when the language uses one, a schema   |

The manifest is the ledger's contract: which languages it uses, which partitions exist, and which partitions each profile asks.
How partitions and profiles work is in [Policy as Code](./policy-languages).

## In practice

Create a zone and a ledger in it, then bind a workspace to that ledger:

```sh
permguard zones create acme
permguard ledgers create main-ledger --zone acme
permguard remote add origin https://permguard.internal:6443
permguard checkout origin/acme/main-ledger
```

Your application names both in every check:

<!--@include: ../snippets/sdk-check.md-->

## Why it matters

<div class="pgx-principles">
  <article><span>Developers</span><h3>One address for your rules.</h3><p>A zone and a ledger name exactly the policies your application is checked against.</p></article>
  <article><span>Platform &amp; IT</span><h3>One zone per blast radius.</h3><p>Put together what one team governs, and split what must never share a token.</p></article>
  <article><span>Security &amp; CISO</span><h3>Access stops at the boundary.</h3><p>A grant on one zone never spills into another zone.</p></article>
</div>

## Go deeper

<div class="pgx-link-grid">
  <a href="./policy-storage"><strong>Git-like Versioning</strong><span>the history inside a ledger</span></a>
  <a href="./policy-languages"><strong>Policy as Code</strong><span>partitions and profiles</span></a>
  <a href="../authority-plane"><strong>Authority Plane</strong><span>grants, scoped to a zone</span></a>
  <a href="./glossary"><strong>Glossary</strong><span>every term, in one line</span></a>
</div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./temporal-authorization"><span>Previous</span><strong><b aria-hidden="true">←</b> Temporal Authorization</strong></a>
  <a class="pgx-pager__next" href="./policy-storage"><span>Next</span><strong>Git-like Versioning <b aria-hidden="true">→</b></strong></a>
</nav>
