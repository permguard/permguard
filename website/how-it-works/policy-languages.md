---
pageClass: pg-page-concepts
title: Policy as Code
description: Authorization rules live in files, versioned and tested like code, in Cedar and Rego side by side.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Policy as code</div>
  <h1>Policies are code.</h1>
  <p>Your authorization rules live in files: versioned, reviewed and tested like the rest of your code.</p>
</div>

## The idea

A [policy](./glossary#policy) is a rule written in a file: who may do what, on what, under which facts.
Because it is a file, it gets what code gets: a history, a review and tests that run before anything reaches production.
You write it in a [policy language](./glossary#policy-language), and one [ledger](./glossary#ledger) can hold Cedar and Rego side by side.

<div class="pgx-languages">
  <article>
    <div class="pgx-language-mark">C</div>
    <div><span>Stable</span><h2>Cedar</h2><p>Typed rules over principal, action and resource, checked against a schema.</p><strong>Best for · application permissions</strong></div>
  </article>
  <article>
    <div class="pgx-language-mark">R</div>
    <div><span>Stable</span><h2>Rego</h2><p>Rules over the request as JSON: who asks, what for, on what.</p><strong>Best for · contextual guardrails</strong></div>
  </article>
  <article class="pgx-languages__experimental">
    <div class="pgx-language-mark" aria-hidden="true"><svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 2.64-6.36"/><path d="M3 4v4h4"/><path d="M12 7.5V12l3 2"/></svg></div>
    <div><span>Experimental</span><h2>Dogwood</h2><p>Rules over what already happened, and within which window.</p><strong>Best for · decisions from history · <a href="./temporal-authorization">Temporal Authorization</a></strong></div>
  </article>
</div>

Inside a ledger, policies are grouped in **partitions**: each partition holds the policies of exactly one language.
A **profile** says which partitions answer a request; a request that names no profile gets `default`.

<div class="pgx-binding" role="img" aria-label="One ledger has two partitions: cedar, holding the Cedar policies, and rego, holding the Rego policies. The profile default asks both partitions and is used when a request names no profile; the profile gateway asks the rego partition alone.">
  <div class="pgx-binding__label"><strong>One ledger</strong><span>partitions hold policies · profiles pick partitions</span></div>
  <div class="pgx-binding__grid">
    <div class="pgx-binding__col">
      <small>PARTITIONS</small>
      <article class="pgx-binding__part--cedar"><strong>cedar</strong><span>the Cedar policies, with their schema</span></article>
      <article class="pgx-binding__part--rego"><strong>rego</strong><span>the Rego policies</span></article>
    </div>
    <div class="pgx-binding__link" aria-hidden="true"><b>→</b></div>
    <div class="pgx-binding__col">
      <small>PROFILES</small>
      <article><strong>default</strong><span>when the request names no profile</span><div class="pgx-binding__chips"><i>cedar</i><i class="is-rego">rego</i></div></article>
      <article><strong>gateway</strong><span>the gateway's rules alone</span><div class="pgx-binding__chips"><i class="is-rego">rego</i></div></article>
    </div>
  </div>
</div>

When several partitions answer, one rule combines them: a deny wins, a failure is a refusal, otherwise a permit wins, and when nothing permits the answer is no.

## In practice

The same rule, alice may read the budget, in the language you choose:

<!--@include: ../snippets/policy-alice.md-->

Start a workspace in both languages, then check and test it on your machine, with no server:

```sh
permguard init quickstart --language cedar,rego
permguard validate    # every local check: manifest, identities, duplicates
permguard test        # the policies decide what the cases say, offline
```

The command line and the Data Plane share one definition of the combining rule, so a test that passes offline decides the same way in production.

## Why it matters

<div class="pgx-principles">
  <article><span>Developers</span><h3>Rules out of the handlers.</h3><p>The rule is one file you test offline, not an <code>if</code> copied into every handler.</p></article>
  <article><span>Platform &amp; IT</span><h3>One place for every rule.</h3><p>Cedar and Rego live side by side in one ledger, delivered and run the same way.</p></article>
  <article><span>Security &amp; CISO</span><h3>Rules you can read and review.</h3><p>Every rule is a file with a history, and every answer names the policy that decided it.</p></article>
</div>

## Go deeper

<div class="pgx-link-grid">
  <a href="./temporal-authorization"><strong>Temporal Authorization</strong><span>decisions from history</span></a>
  <a href="./zones-and-ledgers"><strong>Zones &amp; Ledgers</strong><span>where policies live</span></a>
  <a href="../control-plane"><strong>Control Plane</strong><span>where policies are published</span></a>
  <a href="./glossary"><strong>Glossary</strong><span>every term, in one line</span></a>
</div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./getting-started"><span>Previous</span><strong><b aria-hidden="true">←</b> Getting Started</strong></a>
  <a class="pgx-pager__next" href="./temporal-authorization"><span>Next</span><strong>Temporal Authorization <b aria-hidden="true">→</b></strong></a>
</nav>
