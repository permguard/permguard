---
pageClass: pg-page-concepts
title: Bring Your Own Data Plane
description: Run the Permguard Data Plane by default; build your own only when the decision must live in your process or at a special edge.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Bring your own Data Plane</div>
  <h1>Same policy. Your runtime.</h1>
  <p>The Permguard Data Plane is the default; build your own only when the decision must live inside your process or at a special edge.</p>
</div>

## The idea

The [Data Plane](./glossary#data-plane) is the part that decides: your application asks it, and it answers permit or deny.
Permguard ships one, which runs as a sidecar beside your application or as a remote service.
When the decision must happen inside your own process, or at a special edge, you can build your own Data Plane that reads the same signed [policy](./glossary#policy).

<div class="pgx-system-map pgx-system-map--choice" role="img" aria-label="The Control Plane publishes signed policy once. Two kinds of Data Plane read it: the Permguard Data Plane, the default, as a sidecar or a remote service, and your own Data Plane, for special needs, embedded in your process or at a special edge. Both use the same signed policy and the same decision rule, and both fail closed.">
  <div class="pgx-system-map__frame">
    <div class="pgx-system-map__label"><strong>One policy, two runtimes</strong><span>whoever decides, the policy is published once</span></div>
    <div class="pgx-system-map__host"><small>CONTROL PLANE</small><strong>Signed policy, published once</strong></div>
    <div class="pgx-system-map__bus" aria-hidden="true"></div>
    <div class="pgx-system-map__planes">
      <article><small>DEFAULT</small><strong>Permguard Data Plane</strong><span>sidecar · remote service</span></article>
      <article class="pgx-system-map__optional"><small>SPECIAL NEEDS</small><strong>Your own Data Plane</strong><span>embedded · special edge</span></article>
    </div>
  </div>
  <div class="pgx-system-map__protocols">
    <article><small>SAME POLICY</small><strong>Signed and verified</strong><span>only what is missing travels</span></article>
    <article><small>SAME RULE</small><strong>A deny always wins</strong><span>nothing permitted by default</span></article>
    <article><small>FAIL CLOSED</small><strong>No unverified version</strong><span>an error is never a permit</span></article>
  </div>
</div>

## Which one?

| You need                                            | Run                                   |
| --------------------------------------------------- | ------------------------------------- |
| A decision beside each workload                     | Permguard Data Plane, as a sidecar    |
| One decision service for many callers               | Permguard Data Plane, remote          |
| Signed decision records you do not have to build    | Permguard Data Plane, either way      |
| No network hop at all, not even to localhost        | Your own, embedded in your process    |
| Disconnected, safety-critical or platform-specific  | Your own, at a special edge           |

No row for your own fits?
Run the Permguard Data Plane.

Whichever you run, policy arrives through the [transfer protocol](./glossary#notp) that moves only what is missing and checks it on arrival.
Every version is verified before it is used, and a version that does not verify is never served.

## In practice

The same test cases give the same answers wherever they are decided.
`permguard test` decides them offline, with the same engine and decision rule as the Data Plane.
With `--remote`, it asks the Data Plane your workspace tracks instead:

```sh
# decide every case here, with no server
permguard test
# ask the tracked Data Plane the same cases
permguard test --remote
```

## Why it matters

<div class="pgx-principles">
  <article><span>Developers</span><h3>Start with the default.</h3><p>The Permguard Data Plane already answers as a sidecar or a remote service; build your own only when the decision must live in your process.</p></article>
  <article><span>Platform &amp; IT</span><h3>Nothing extra to build.</h3><p>The Permguard Data Plane already verifies each policy version and keeps signed records of its decisions.</p></article>
  <article><span>Security &amp; CISO</span><h3>One policy, wherever it runs.</h3><p>A policy is written, reviewed and published once, whoever decides with it, and an unverified version is never served.</p></article>
</div>

## Go deeper

<div class="pgx-link-grid">
  <a href="../data-plane"><strong>Data Plane</strong><span>the default runtime</span></a>
  <a href="../control-plane"><strong>Control Plane</strong><span>where policy is published</span></a>
  <a href="./decision-lifecycle"><strong>Decision Path</strong><span>request → evaluation → answer</span></a>
  <a href="./glossary"><strong>Glossary</strong><span>every term, in one line</span></a>
</div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./architecture"><span>Previous</span><strong><b aria-hidden="true">←</b> Server, Host &amp; Planes</strong></a>
  <a class="pgx-pager__next" href="./glossary"><span>Next</span><strong>Glossary <b aria-hidden="true">→</b></strong></a>
</nav>
