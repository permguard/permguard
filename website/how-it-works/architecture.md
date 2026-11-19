---
pageClass: pg-page-concepts
title: Server, Host and Planes
description: One Permguard Server is one Host plus the planes you deploy, each plane with one job.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Architecture</div>
  <h1>One Host. One job per plane.</h1>
  <p>A Permguard Server is one Host and the planes you choose to run, together in one process or apart.</p>
</div>

## The idea

A Permguard Server is one running program: one [Host](./glossary#host) and the planes you deploy.
The Host owns what every part shares: identity, keys, audit and membership.
A plane owns one job: the [Authority Plane](./glossary#authority-plane) admits callers, the [Control Plane](./glossary#control-plane) publishes policy, the [Data Plane](./glossary#data-plane) decides.

<div class="pgx-system-map" role="img" aria-label="One Permguard Server contains one Host, on port 5443, and the planes it composes: the Authority Plane on port 8443, the Control Plane on 6443 and the Data Plane on 7443. The Trust Plane is next on the roadmap and not served today.">
  <div class="pgx-system-map__frame">
    <div class="pgx-system-map__label"><strong>Permguard Server</strong><span>one Host · the planes you deploy</span></div>
    <div class="pgx-system-map__host"><small>HOST · :5443</small><strong>Identity · Keys · Audit · Membership</strong></div>
    <div class="pgx-system-map__bus" aria-hidden="true"></div>
    <div class="pgx-system-map__planes">
      <article><small>AUTHORITY PLANE · :8443</small><strong>Admit</strong><span>identities · access tokens</span></article>
      <article><small>CONTROL PLANE · :6443</small><strong>Govern</strong><span>policies · decision logs · events</span></article>
      <article><small>DATA PLANE · :7443</small><strong>Decide</strong><span>beside the workload</span></article>
    </div>
    <div class="pgx-system-map__next"><small>TRUST PLANE · NEXT</small><span>authority continuity with PIC-X · not served today</span></div>
  </div>
</div>

Each part keeps its own standard port.

| Part            | Port   | Its job                                         |
| --------------- | -----: | ----------------------------------------------- |
| Server Host     | `5443` | discovery, health, readiness, version, metrics  |
| Control Plane   | `6443` | policies, decision logs, events                 |
| Data Plane      | `7443` | decisions, beside the workload                  |
| Authority Plane | `8443` | identities, access keys, tokens                 |
| Trust Plane     |      — | next on the roadmap; not served today           |

Run every plane in one process, all-in-one, or split them so that each process runs one Host with one plane.
The ports stay the same either way.

## In practice

One address tells a client which planes a server runs.
Ask the Host:

```sh
curl -s http://127.0.0.1:5443/.well-known/server-configuration | jq
```

```json
{
  "planes": {
    "control-plane": {
      "server_configuration": "http://127.0.0.1:6443/.well-known/server-configuration"
    },
    "data-plane": {
      "server_configuration": "http://127.0.0.1:7443/.well-known/server-configuration"
    }
  }
}
```

Each plane then describes itself at the address it names.
To walk the whole chain from one address, run `permguard discover http://127.0.0.1:5443`.

## Why it matters

<div class="pgx-principles">
  <article><span>Developers</span><h3>One address to start.</h3><p>Point a client at the Host and it learns which planes the server runs and where each one lives.</p></article>
  <article><span>Platform &amp; IT</span><h3>Together or apart.</h3><p>Run every plane in one process or split them by plane, and each part keeps its standard port.</p></article>
  <article><span>Security &amp; CISO</span><h3>One owner for keys and audit.</h3><p>The Host keeps identity, keys and audit for every plane: a plane never creates a second key manager or audit trail.</p></article>
</div>

## Go deeper

<div class="pgx-link-grid">
  <a href="../authority-plane"><strong>Authority Plane</strong><span>who may call Permguard itself</span></a>
  <a href="../control-plane"><strong>Control Plane</strong><span>zones · ledgers · signed policy</span></a>
  <a href="../data-plane"><strong>Data Plane</strong><span>decides beside the workload</span></a>
  <a href="../trust-plane"><strong>Trust Plane</strong><span>next on the roadmap · PIC-X</span></a>
</div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./evidence"><span>Previous</span><strong><b aria-hidden="true">←</b> Verifiable Evidence</strong></a>
  <a class="pgx-pager__next" href="./bring-your-own-data-plane"><span>Next</span><strong>Bring Your Own Data Plane <b aria-hidden="true">→</b></strong></a>
</nav>
