---
pageClass: pg-page-concepts
title: Policy Delivery
description: How a policy commit becomes the version every Data Plane decides with.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Policy delivery</div>
  <h1>Commit once. Every PDP proves it.</h1>
  <p>A policy reaches production as a signed, immutable version, and each Data Plane verifies it before it decides with it.</p>
</div>

## Nine steps, three places

<div class="pgx-delivery-wrap">
<div class="pgx-delivery" role="img" aria-label="Policy delivery in three places. In the workspace, offline: author the policy, validate it, test it with the Data Plane's engine. apply sends only the missing objects to the Control Plane, which rehashes every object, checks the closure is complete and advances the ledger head once, signed. Each Data Plane pulls on its own interval: it fetches only what is missing, verifies the signed head, refuses a rollback and checks the whole closure, switches its checkpoint atomically, then compiles the new version once.">
  <section class="pgx-delivery__lane">
    <header><small>Workspace · offline</small><strong>Your machine or CI</strong></header>
    <ol>
      <li><b>01</b><div><strong>Author</strong><span>Cedar or Rego, as files</span></div></li>
      <li><b>02</b><div><strong>Validate</strong><span>manifest · identities · duplicates</span></div></li>
      <li><b>03</b><div><strong>Test</strong><span>the Data Plane's engine, no server</span></div></li>
    </ol>
  </section>
  <div class="pgx-delivery__hop"><code>apply</code><i><em></em></i><span>missing objects only</span></div>
  <section class="pgx-delivery__lane">
    <header><small>Control Plane · :6443</small><strong>Publishes</strong></header>
    <ol>
      <li><b>04</b><div><strong>Accept</strong><span>every object rehashed · closure complete</span></div></li>
      <li><b>05</b><div><strong>Sign the head</strong><span>the ref advances once, counter + 1</span></div></li>
    </ol>
  </section>
  <div class="pgx-delivery__hop"><code>mirror</code><i><em></em></i><span>pulled every interval</span></div>
  <section class="pgx-delivery__lane pgx-delivery__lane--accent">
    <header><small>Data Plane · :7443</small><strong>Proves, then serves</strong></header>
    <ol>
      <li><b>06</b><div><strong>Fetch</strong><span>only what it does not hold</span></div></li>
      <li><b>07</b><div><strong>Verify</strong><span>signed head · no rollback · whole closure</span></div></li>
      <li><b>08</b><div><strong>Switch</strong><span>one atomic checkpoint</span></div></li>
      <li><b>09</b><div><strong>Compile</strong><span>once per commit, off the request path</span></div></li>
    </ol>
  </section>
</div>
</div>

The workspace never talks to a Data Plane.
Each Data Plane pulls on its own interval, and a decision never waits for the Control Plane: if it is down, the plane keeps deciding with the version it already verified.

## The switch

<div class="pgx-switch" role="img" aria-label="Timeline of one Data Plane. Commit C2 answers every request until the checkpoint switches to C3 in one step. From then on C3 answers. There is no moment when neither, or a mix of both, answers.">
  <div class="pgx-switch__run"><small>answering</small><strong>C2</strong><span>head H11</span></div>
  <div class="pgx-switch__cut"><b>switch</b><span>one append</span></div>
  <div class="pgx-switch__run pgx-switch__run--next"><small>answering</small><strong>C3</strong><span>head H12</span></div>
</div>

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card"><span>Before</span><h3>The old version answers</h3><p>Objects land first and change nothing. A crash mid-round leaves the previous checkpoint in force.</p></article>
  <article class="pgx-card pgx-card--accent"><span>At the switch</span><h3>One step, whole versions</h3><p>The checkpoint moves only once the signed head and the complete closure verify. Each request reads it once.</p></article>
  <article class="pgx-card"><span>After</span><h3>A version never changes</h3><p>A lower counter is a rollback, the same counter with another digest an equivocation: both are refused.</p></article>
</div>

<div class="pgx-note"><strong>No silent fallback.</strong><span>A commit this engine cannot load is not served, and neither is the one before it: the ledger answers <code>ledger_incompatible</code> (503) until the next commit.</span></div>

## What you run

```sh
permguard validate                # manifest, identities, duplicates
permguard test                    # your cases, the Data Plane's engine
permguard plan                    # what apply would change
permguard apply -m "tighten exports"
permguard verify                  # remote signed head, local closure
permguard test --remote           # the same cases, on the Data Plane
```

`validate`, `test` and `plan` touch no server; `apply` uploads the missing objects and advances the signed head.
`test` runs the same engine and decision algebra as the Data Plane: same commit, same engine build, same answer.
`history --limit 5` lists the last commits of the tracked ref; `check` asks the Data Plane one question by hand.

## What you can watch

The mirror loop is declared under `dataPlane.mirrors`; this is the block of the [Docker configuration](https://github.com/permguard/permguard/blob/main/crates/permguard-all-in-one/config.docker.yml), comments trimmed:

```yaml
dataPlane:
  mirrors:
    enabled: "true"
    interval: "15s"        # the default is 30s
    timeout: "1m"
    parallelism: "4"
```

A new head reaches a Data Plane within one round: `interval × (1 + jitter)` at worst, plus the time to fetch and verify.
A round that is still working when the next tick comes skips it: rounds never overlap.

| Signal                              | Kind    | What it tells you                                                          |
| ----------------------------------- | ------- | -------------------------------------------------------------------------- |
| `mirrors.interval`                  | setting | how often a round starts; `30s` by default, jitter `0.1` spreads replicas  |
| `mirrors.timeout`                   | setting | per ledger: a ledger past it is abandoned for this round; `2m` by default  |
| `mirrors.stale_after`               | setting | past this age the plane alarms, and still answers                          |
| `mirrors.expire_after`              | setting | past this age the plane refuses with `ledger_expired` (503)                |
| `permguard_sync_mirror_age_seconds` | metric  | seconds since the stalest mirror last synchronized                         |
| `permguard_sync_warmed_total`       | metric  | by outcome: `ready`, or `blocked` when this engine cannot serve the commit |
| `sync.mirrored`                     | log     | the mirror advanced                                                        |
| `sync.ledger_ready`                 | log     | the new commit is compiled and ready to answer                             |

Every scalar setting also reads from the environment, which beats the file: `PERMGUARD_MIRRORS_INTERVAL`, `PERMGUARD_MIRRORS_STALE_AFTER` and so on.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./notp"><span>Previous</span><strong><b aria-hidden="true">←</b> NOTP Protocol</strong></a>
  <a class="pgx-pager__next" href="./decision-lifecycle"><span>Next</span><strong>Decision Path <b aria-hidden="true">→</b></strong></a>
</nav>
