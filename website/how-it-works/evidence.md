---
pageClass: pg-page-concepts
title: Verifiable Evidence
description: Every decision leaves a signed record chained to the one before, which you can read back, verify and export.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Verifiable evidence</div>
  <h1>Every decision, on record.</h1>
  <p>Who asked, for what, under which policy, and the answer: kept in a record nobody can change unnoticed.</p>
</div>

## The idea

Every [decision](./glossary#decision) leaves a record, the [evidence](./glossary#evidence): who asked, what, on which resource, under which policy, permit or deny.
Each record is chained to the one before it and signed, so changing, removing or reordering any of them shows.
In the shipped configurations the answer leaves only once its record is durable.

<div class="pgx-record-map">
  <svg class="pgx-hv pgx-record-map__wide" viewBox="0 0 800 276" role="img" aria-label="Decision records in a chain: alice reading the budget, permitted, then bob, denied, then the next decision. Each record is chained to the one before it, and a signature covers the chain. You read the records back and verify them with the Permguard CLI, and Permguard Admin exports them as JSON Lines or CSV to your SIEM and threat intelligence.">
    <g class="pgx-hv__flows">
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M176 60 H214"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M396 60 H434"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M616 60 H650"/>
      <path class="pgx-hv__flow pgx-hv__flow--identity" d="M305 112 V146 H125 V182"/>
      <path class="pgx-hv__flow pgx-hv__flow--identity" d="M305 146 H400 V182"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M531 230 H544"/>
    </g>
    <text class="pgx-hv__m" x="195" y="48" text-anchor="middle">chain</text>
    <text class="pgx-hv__m" x="415" y="48" text-anchor="middle">chain</text>
    <text class="pgx-hv__m" x="633" y="48" text-anchor="middle">sign</text>
    <g class="pgx-hv__node"><rect x="0.5" y="12.5" width="170" height="94" rx="14"/><text class="pgx-hv__k" x="85" y="40" text-anchor="middle">RECORD</text><text class="pgx-hv__s" x="85" y="65" text-anchor="middle">alice · budget</text><text class="pgx-hv__m" x="85" y="88" text-anchor="middle">permit</text></g>
    <g class="pgx-hv__node"><rect x="220.5" y="12.5" width="170" height="94" rx="14"/><text class="pgx-hv__k" x="305" y="40" text-anchor="middle">RECORD</text><text class="pgx-hv__s" x="305" y="65" text-anchor="middle">bob · budget</text><text class="pgx-hv__m" x="305" y="88" text-anchor="middle">deny</text></g>
    <g class="pgx-hv__node"><rect x="440.5" y="12.5" width="170" height="94" rx="14"/><text class="pgx-hv__k" x="525" y="40" text-anchor="middle">RECORD</text><text class="pgx-hv__s" x="525" y="65" text-anchor="middle">the next one</text><text class="pgx-hv__m" x="525" y="88" text-anchor="middle">…</text></g>
    <g class="pgx-hv__node pgx-hv__node--cp"><rect x="656.5" y="12.5" width="143" height="94" rx="14"/><text class="pgx-hv__k" x="728" y="40" text-anchor="middle">SIGNED</text><text class="pgx-hv__s" x="728" y="65" text-anchor="middle">tamper shows</text><text class="pgx-hv__m" x="728" y="88" text-anchor="middle">covers the chain</text></g>
    <g class="pgx-hv__node"><rect x="0.5" y="188.5" width="250" height="84" rx="14"/><text class="pgx-hv__k" x="125" y="214" text-anchor="middle">READ · VERIFY</text><text class="pgx-hv__s" x="125" y="238" text-anchor="middle">Permguard CLI</text><text class="pgx-hv__m" x="125" y="259" text-anchor="middle">chain · signatures</text></g>
    <g class="pgx-hv__node"><rect x="275.5" y="188.5" width="250" height="84" rx="14"/><text class="pgx-hv__k" x="400" y="214" text-anchor="middle">EXPORT</text><text class="pgx-hv__s" x="400" y="238" text-anchor="middle">Permguard Admin</text><text class="pgx-hv__m" x="400" y="259" text-anchor="middle">JSON Lines · CSV</text></g>
    <g class="pgx-hv__node"><rect x="549.5" y="188.5" width="250" height="84" rx="14"/><text class="pgx-hv__k" x="674" y="214" text-anchor="middle">YOUR TOOLS</text><text class="pgx-hv__s" x="674" y="238" text-anchor="middle">SIEM · threat intel</text><text class="pgx-hv__m" x="674" y="259" text-anchor="middle">beside your other logs</text></g>
  </svg>
  <svg class="pgx-hv pgx-record-map__compact" viewBox="0 0 340 606" role="img" aria-label="Decision records in a chain: alice reading the budget, permitted, then bob, denied, then the next decision. Each record is chained to the one before it, and a signature covers the chain. You read the records back and verify them with the Permguard CLI, and Permguard Admin exports them as JSON Lines or CSV to your SIEM and threat intelligence.">
    <g class="pgx-hv__flows">
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M170 70 V90"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M170 164 V184"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M170 258 V278"/>
      <path class="pgx-hv__flow pgx-hv__flow--identity" d="M170 352 V374 H92 V398"/>
      <path class="pgx-hv__flow pgx-hv__flow--identity" d="M170 374 H248 V398"/>
      <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M248 486 V510"/>
    </g>
    <text class="pgx-hv__m" x="184" y="85">chain</text>
    <text class="pgx-hv__m" x="184" y="179">chain</text>
    <text class="pgx-hv__m" x="184" y="273">sign</text>
    <g class="pgx-hv__node"><rect x="20.5" y="0.5" width="300" height="64" rx="14"/><text class="pgx-hv__k" x="170" y="25" text-anchor="middle">RECORD · PERMIT</text><text class="pgx-hv__s" x="170" y="50" text-anchor="middle">alice · budget</text></g>
    <g class="pgx-hv__node"><rect x="20.5" y="94.5" width="300" height="64" rx="14"/><text class="pgx-hv__k" x="170" y="119" text-anchor="middle">RECORD · DENY</text><text class="pgx-hv__s" x="170" y="144" text-anchor="middle">bob · budget</text></g>
    <g class="pgx-hv__node"><rect x="20.5" y="188.5" width="300" height="64" rx="14"/><text class="pgx-hv__k" x="170" y="213" text-anchor="middle">RECORD</text><text class="pgx-hv__s" x="170" y="238" text-anchor="middle">the next one</text></g>
    <g class="pgx-hv__node pgx-hv__node--cp"><rect x="20.5" y="282.5" width="300" height="64" rx="14"/><text class="pgx-hv__k" x="170" y="307" text-anchor="middle">SIGNED</text><text class="pgx-hv__s" x="170" y="332" text-anchor="middle">tampering shows</text></g>
    <g class="pgx-hv__node"><rect x="20.5" y="404.5" width="143" height="76" rx="14"/><text class="pgx-hv__k" x="92" y="430" text-anchor="middle">VERIFY</text><text class="pgx-hv__s" x="92" y="453" text-anchor="middle">CLI</text><text class="pgx-hv__m" x="92" y="471" text-anchor="middle">chain · keys</text></g>
    <g class="pgx-hv__node"><rect x="176.5" y="404.5" width="144" height="76" rx="14"/><text class="pgx-hv__k" x="248" y="430" text-anchor="middle">EXPORT</text><text class="pgx-hv__s" x="248" y="453" text-anchor="middle">Admin</text><text class="pgx-hv__m" x="248" y="471" text-anchor="middle">JSONL · CSV</text></g>
    <g class="pgx-hv__node"><rect x="176.5" y="516.5" width="144" height="76" rx="14"/><text class="pgx-hv__k" x="248" y="542" text-anchor="middle">YOUR TOOLS</text><text class="pgx-hv__s" x="248" y="565" text-anchor="middle">SIEM</text><text class="pgx-hv__m" x="248" y="583" text-anchor="middle">threat intel</text></g>
  </svg>
</div>

- **What it proves:** what was decided, in which order, under which policy version, and which key signed it.
- **What it does not prove:** that the policy was right: a record shows what was decided, not whether the rule deserved to exist.

## In practice

```sh
# read one decision back, by the id the application was given
permguard decisions get 01a1f111-df65-77cf-b171-3facea0cbc27 \
  --zone quickstart --ledger policies

# check the chain, and the signatures against the published keys
permguard decisions list --zone quickstart --ledger policies \
  --verify --keys data-plane-keys.json

# export a snapshot and verify it offline, without any server
permguard decisions export --zone quickstart --ledger policies \
  -o json > decisions.json
permguard decisions verify --file decisions.json --keys data-plane-keys.json
```

With the keys, the check does not depend on trusting the server that served the records.
[Permguard Admin](./install#permguard-admin) exports its Decision logs page as JSON Lines or CSV, ready for your [SIEM and threat intelligence](./glossary#siem).

## Why it matters

<div class="pgx-principles">
  <article><span>Developers</span><h3>One id finds the record.</h3><p>Every answer carries a decision id, and that id reads the record behind it back.</p></article>
  <article><span>Platform & IT</span><h3>Into the tools you run.</h3><p>Export decisions as JSON Lines or CSV and analyse them beside your other logs.</p></article>
  <article><span>Security & CISO</span><h3>Proof, not promises.</h3><p>Records are signed and chained, so anyone holding the keys can check that nobody altered them.</p></article>
</div>

## Go deeper

<div class="pgx-link-grid">
  <a href="./decision-lifecycle"><strong>Decision Path</strong><span>where a record comes from</span></a>
  <a href="../data-plane"><strong>Data Plane</strong><span>where records are written</span></a>
  <a href="./architecture"><strong>Server, Host &amp; Planes</strong><span>who keeps the records</span></a>
  <a href="./glossary"><strong>Glossary</strong><span>every term, in one line</span></a>
</div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./decision-lifecycle"><span>Previous</span><strong><b aria-hidden="true">←</b> Decision Path</strong></a>
  <a class="pgx-pager__next" href="./architecture"><span>Next</span><strong>Server, Host &amp; Planes <b aria-hidden="true">→</b></strong></a>
</nav>
