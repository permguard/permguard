---
pageClass: pg-page-concepts
title: Git-like Versioning
description: Every policy change is a commit, every published version is signed, and history is never rewritten.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Git-like versioning</div>
  <h1>Policy has history.</h1>
  <p>Every change is a commit, every published version is signed, and nothing is ever overwritten.</p>
</div>

## The idea

Every policy version is immutable, and its history cannot be rewritten: who changed what, and when, stays provable.
Permguard takes Git's model, commits linked into a history, and rebuilds it for policy: it is not Git, on purpose.
Each change to a [ledger](./glossary#ledger) is a commit, the Control Plane signs the version it accepts, the [signed head](./glossary#signed-head), and every Data Plane receives that exact version.

<div class="pgx-vflow" role="img" aria-label="Three commits in a row: C1, the first policy; C2, read-only budget, which follows C1; C3, add contractors, which follows C2. The Control Plane signs C3 as the accepted version. The transfer protocol moves only what is missing to every Data Plane and checks it on arrival, so each Data Plane holds C3, verified.">
  <section class="pgx-vflow__commits">
    <small>HISTORY · NEVER REWRITTEN</small>
    <div class="pgx-vflow__row">
      <article><b>C1</b><span>first policy</span></article>
      <i aria-hidden="true">→</i>
      <article><b>C2</b><span>read-only budget</span></article>
      <i aria-hidden="true">→</i>
      <article class="is-current"><b>C3</b><span>add contractors</span></article>
    </div>
  </section>
  <i class="pgx-vflow__step" aria-hidden="true">→</i>
  <section class="pgx-vflow__head">
    <small>SIGNED HEAD</small>
    <strong>C3 is the version</strong>
    <span>signed by the Control Plane</span>
  </section>
  <div class="pgx-vflow__wire" aria-hidden="true"><b>NOTP</b><span>only what is missing · checked on arrival</span></div>
  <section class="pgx-vflow__planes">
    <small>DATA PLANES</small>
    <span><b>C3</b> verified</span>
    <span><b>C3</b> verified</span>
    <span><b>C3</b> verified</span>
  </section>
</div>

The transfer protocol, [NOTP](./glossary#notp), moves only what is missing and checks it on arrival, so every Data Plane stays in sync with the signed version.

## In practice

The everyday workflow is the one you know: check, see the change, publish it, read the history.

```sh
permguard validate                                  # every local check, offline
permguard plan                                      # what would change, offline
permguard apply -m "budget: read-only for alice"    # commit, then publish
permguard history                                   # every version, newest first
```

| Like Git, unlike Git on purpose | Git                             | Permguard                                                     |
| ------------------------------- | ------------------------------- | ------------------------------------------------------------- |
| History                         | commits linked to their parents | the same: a commit never changes                              |
| What a commit may hold          | any file, any bytes             | only validated policies, schemas and the manifest             |
| Form                            | the bytes as written            | one canonical form; anything else is refused                  |
| Rewriting history               | a force push can rewrite it     | refused: history only moves forward, and rollbacks are caught |
| Proof of publication            | signatures are optional         | every accepted version is signed by the Control Plane         |

Plain Git in production would accept anything you commit.
Permguard accepts only policy it has validated, keeps one canonical form of it, and refuses any rewrite or rollback.

## Why it matters

<div class="pgx-principles">
  <article><span>Developers</span><h3>A workflow you already know.</h3><p>Commit, history, and <code>plan</code> then <code>apply</code>, much like diff then push.</p></article>
  <article><span>Platform &amp; IT</span><h3>Every plane on the same version.</h3><p>Data Planes receive only what is missing, check it, and hold the signed version.</p></article>
  <article><span>Security &amp; CISO</span><h3>Your back is covered.</h3><p>Every version is immutable and signed, so who changed what, and when, is provable.</p></article>
</div>

## Go deeper

<div class="pgx-link-grid">
  <a href="./policy-lifecycle"><strong>Policy Delivery</strong><span>commit → signed version → running PDP</span></a>
  <a href="./zones-and-ledgers"><strong>Zones &amp; Ledgers</strong><span>where the history lives</span></a>
  <a href="../control-plane"><strong>Control Plane</strong><span>where versions are signed</span></a>
  <a href="./glossary"><strong>Glossary</strong><span>every term, in one line</span></a>
</div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./zones-and-ledgers"><span>Previous</span><strong><b aria-hidden="true">←</b> Zones &amp; Ledgers</strong></a>
  <a class="pgx-pager__next" href="./policy-lifecycle"><span>Next</span><strong>Policy Delivery <b aria-hidden="true">→</b></strong></a>
</nav>
