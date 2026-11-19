---
pageClass: pg-page-concepts
title: Policy Delivery
description: How a policy goes from your machine to every Data Plane, as a signed version that never changes.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Policy delivery</div>
  <h1>From your laptop to every decision.</h1>
  <p>You publish a policy once, and every place that decides checks it before using it.</p>
</div>

## The idea

A [policy](./glossary#policy) is a rule written in a file: who may do what, on what.
You write it and test it on your machine, then publish it once to the [Control Plane](./glossary#control-plane), which signs it as a new version.
Every [Data Plane](./glossary#data-plane), the [PDP](./glossary#pdp) that answers your applications, copies that version, checks the signature, and only then switches to it.

<div class="pgx-delivery-map">
  <svg class="pgx-hv pgx-delivery-map__wide" viewBox="0 0 800 290" role="img" aria-label="A policy is written and tested offline on your machine, published with apply to the Control Plane, which signs it as a version that never changes. Every Data Plane copies the version, checks its signature, switches to it in one step, and then decides with it.">
    <g class="pgx-hv__flows">
      <path class="pgx-hv__flow pgx-hv__flow--identity" d="M186 145 H256"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M468 145 H516 V54 H556"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M468 145 H556"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M516 145 V236 H556"/>
    </g>
    <text class="pgx-hv__d" x="221" y="133" text-anchor="middle">apply</text>
    <g class="pgx-hv__node"><rect x="0.5" y="103.5" width="180" height="84" rx="14"/><text class="pgx-hv__k" x="90" y="131" text-anchor="middle">YOUR MACHINE</text><text class="pgx-hv__s" x="90" y="155" text-anchor="middle">Write · test</text><text class="pgx-hv__m" x="90" y="175" text-anchor="middle">offline, no server</text></g>
    <g class="pgx-hv__node pgx-hv__node--cp"><rect x="262.5" y="95.5" width="200" height="100" rx="14"/><text class="pgx-hv__k" x="362" y="125" text-anchor="middle">CONTROL PLANE</text><text class="pgx-hv__s" x="362" y="151" text-anchor="middle">Signs the version</text><text class="pgx-hv__m" x="362" y="173" text-anchor="middle">a version never changes</text></g>
    <g class="pgx-hv__node"><rect x="562.5" y="16.5" width="237" height="76" rx="14"/><text class="pgx-hv__k" x="681" y="42" text-anchor="middle">DATA PLANE</text><text class="pgx-hv__s" x="681" y="64" text-anchor="middle">Copy · check · switch</text><text class="pgx-hv__m" x="681" y="82" text-anchor="middle">then decide with it</text></g>
    <g class="pgx-hv__node"><rect x="562.5" y="107.5" width="237" height="76" rx="14"/><text class="pgx-hv__k" x="681" y="133" text-anchor="middle">DATA PLANE</text><text class="pgx-hv__s" x="681" y="155" text-anchor="middle">Copy · check · switch</text><text class="pgx-hv__m" x="681" y="173" text-anchor="middle">then decide with it</text></g>
    <g class="pgx-hv__node"><rect x="562.5" y="198.5" width="237" height="76" rx="14"/><text class="pgx-hv__k" x="681" y="224" text-anchor="middle">DATA PLANE</text><text class="pgx-hv__s" x="681" y="246" text-anchor="middle">Copy · check · switch</text><text class="pgx-hv__m" x="681" y="264" text-anchor="middle">then decide with it</text></g>
  </svg>
  <svg class="pgx-hv pgx-delivery-map__compact" viewBox="0 0 340 420" role="img" aria-label="A policy is written and tested offline on your machine, published with apply to the Control Plane, which signs it as a version that never changes. Every Data Plane copies the version, checks its signature, switches to it in one step, and then decides with it.">
    <g class="pgx-hv__flows">
      <path class="pgx-hv__flow pgx-hv__flow--identity" d="M170 92 V136"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M170 244 V288"/>
    </g>
    <text class="pgx-hv__d" x="184" y="119">apply</text>
    <text class="pgx-hv__m" x="184" y="271">copied by each</text>
    <g class="pgx-hv__node"><rect x="20.5" y="0.5" width="300" height="86" rx="14"/><text class="pgx-hv__k" x="170" y="28" text-anchor="middle">YOUR MACHINE</text><text class="pgx-hv__s" x="170" y="54" text-anchor="middle">Write · test</text><text class="pgx-hv__m" x="170" y="75" text-anchor="middle">offline, no server</text></g>
    <g class="pgx-hv__node pgx-hv__node--cp"><rect x="20.5" y="142.5" width="300" height="96" rx="14"/><text class="pgx-hv__k" x="170" y="172" text-anchor="middle">CONTROL PLANE</text><text class="pgx-hv__s" x="170" y="198" text-anchor="middle">Signs the version</text><text class="pgx-hv__m" x="170" y="221" text-anchor="middle">a version never changes</text></g>
    <g class="pgx-hv__node pgx-delivery-map__ghost"><rect x="36.5" y="294.5" width="268" height="96" rx="14"/></g>
    <g class="pgx-hv__node pgx-delivery-map__ghost"><rect x="28.5" y="302.5" width="284" height="96" rx="14"/></g>
    <g class="pgx-hv__node"><rect x="20.5" y="310.5" width="300" height="96" rx="14"/><text class="pgx-hv__k" x="170" y="340" text-anchor="middle">EVERY DATA PLANE</text><text class="pgx-hv__s" x="170" y="366" text-anchor="middle">Copy · check · switch</text><text class="pgx-hv__m" x="170" y="389" text-anchor="middle">then decide with it</text></g>
  </svg>
</div>

- A published version never changes: a new rule is a new version.
- Until the switch, a Data Plane keeps answering with the version it already holds, and the switch replaces the whole version in one step.
- If a Data Plane cannot load the new version, it does not fall back silently to the old one: it answers with an error until the next version arrives.
- Deciding never waits for the Control Plane: if it is down, each Data Plane keeps deciding with the version it already checked.

## In practice

```sh
permguard validate                    # check the files, offline
permguard test                        # run your test cases, offline
permguard plan                        # see what apply would change
permguard apply -m "tighten exports"  # publish a new signed version
permguard test --remote               # the same cases, on the Data Plane
```

`permguard test` runs the same engine as the Data Plane: same version, same engine build, same answer.
Each Data Plane picks up the new version on its own schedule, every 30 seconds by default.

## Why it matters

<div class="pgx-principles">
  <article><span>Developers</span><h3>Test before you ship.</h3><p>A change is tested offline with the Data Plane's own engine, before any application depends on it.</p></article>
  <article><span>Platform & IT</span><h3>Deciding never waits.</h3><p>Data Planes keep deciding with the version they hold while the Control Plane is down; only new versions wait for it.</p></article>
  <article><span>Security & CISO</span><h3>Only signed versions run.</h3><p>A Data Plane decides only with a version whose signature it checked, and never slips back silently to an older one.</p></article>
</div>

## Go deeper

<div class="pgx-link-grid">
  <a href="./policy-storage"><strong>Git-like Versioning</strong><span>commits · history · signed versions</span></a>
  <a href="./decision-lifecycle"><strong>Decision Path</strong><span>what happens to one request</span></a>
  <a href="../control-plane"><strong>Control Plane</strong><span>where policies are published</span></a>
  <a href="../data-plane"><strong>Data Plane</strong><span>where they are checked and used</span></a>
</div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./policy-storage"><span>Previous</span><strong><b aria-hidden="true">←</b> Git-like Versioning</strong></a>
  <a class="pgx-pager__next" href="./decision-lifecycle"><span>Next</span><strong>Decision Path <b aria-hidden="true">→</b></strong></a>
</nav>
