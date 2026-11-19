---
pageClass: pg-page-concepts
title: Command Line
description: "One CLI from authoring to evidence: workspaces, zones and ledgers, decisions, the Authority Plane and Server operations."
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero pgx-doc-hero--overview pgx-cli-hero">
  <div class="pgx-kicker">Command Line</div>
  <h1>One CLI, authoring to evidence.</h1>
  <p>The <code>permguard</code> command line writes and tests policy on your machine, publishes it, asks for decisions, reads the evidence and operates the Servers.</p>
</div>

This section is the reference for `permguard`, the Permguard command line, as of release 0.1.33.
Every command and flag on these pages is the one its `--help` prints, and every command answers `-h` the same way at every depth.
Each command reaches exactly one target, and a flag that names another target is refused rather than followed.

## Where each command goes

<div class="pgx-cli-map" role="img" aria-label="The permguard CLI reaches six targets: the local workspace; the Control Plane on port 6443 for zones, ledgers, publishing and evidence reads; the Data Plane on port 7443 for decisions; the Authority Plane on port 8443 for accounts and tokens; the Host listener for host, gc and evidence anchors; and, offline, a stopped Server's volume for restore, migrate and recovery.">
  <div class="pgx-cli-map__cli"><small>PERMGUARD CLI</small><strong>permguard</strong><span>one command · one target · no fallback</span></div>
  <div class="pgx-cli-map__bus" aria-hidden="true"></div>
  <div class="pgx-cli-map__targets">
    <article><small>LOCAL · -w</small><strong>Workspace</strong><span>init · validate · test · plan · status · objects</span></article>
    <article class="pgx-cli-map__accent"><small>CONTROL PLANE · 6443</small><strong>Publish and read</strong><span>zones · ledgers · apply · pull · decisions · events</span></article>
    <article><small>DATA PLANE · 7443</small><strong>Decide</strong><span>check · test --remote</span></article>
    <article><small>AUTHORITY PLANE · 8443</small><strong>Accounts and tokens</strong><span>authority</span></article>
    <article><small>HOST LISTENER</small><strong>Operate a Host</strong><span>host · evidence · gc · reclaim</span></article>
    <article class="pgx-cli-map__offline"><small>OFFLINE · --volume</small><strong>A stopped Server</strong><span>restore · migrate · backup verify</span></article>
  </div>
</div>

The address of each target comes from a flag, an environment variable or the configuration file, in that order: see [Configuration](./command-line/configuration).
`inspect` asks both the Control Plane and the Data Plane at once, and `discover` starts from any address you give it.

## The command families

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card pgx-card--accent"><span>Workspace</span><h3>Author and publish</h3><p>Write policy as files, prove it offline, then publish it as a signed commit.</p><p class="pgx-cli-family"><code>init</code><code>validate</code><code>test</code><code>plan</code><code>apply</code><code>pull</code></p></article>
  <article class="pgx-card"><span>Catalog</span><h3>Zones and ledgers</h3><p>Create, rename, archive, export and import the containers policy lives in.</p><p class="pgx-cli-family"><code>zones</code><code>ledgers</code></p></article>
  <article class="pgx-card"><span>Evidence</span><h3>Decide and prove</h3><p>Ask for a decision, then read, follow, export and verify what was recorded.</p><p class="pgx-cli-family"><code>check</code><code>decisions</code><code>events</code><code>evidence</code></p></article>
  <article class="pgx-card"><span>Authority</span><h3>Who may call</h3><p>Identities, their scopes and access keys, and the tokens every Plane verifies.</p><p class="pgx-cli-family"><code>authority</code></p></article>
  <article class="pgx-card"><span>Operations</span><h3>Run the Servers</h3><p>Find and inspect the Planes; manage a Host's identity, members, keys, audit, streams and backups.</p><p class="pgx-cli-family"><code>discover</code><code>inspect</code><code>host</code><code>gc</code></p></article>
  <article class="pgx-card"><span>Offline</span><h3>Repair a volume</h3><p>Restore, migrate or verify a stopped Server's volume, and recover the administrator's key.</p><p class="pgx-cli-family"><code>restore</code><code>migrate</code><code>backup</code></p></article>
</div>

## Install it

Install the CLI from [Install](./how-it-works/install#permguard-cli), then confirm the release with `permguard version`.
[Getting Started](./how-it-works/getting-started) runs one policy from a new workspace to a decision.

```sh
permguard version
permguard completion zsh > "${fpath[1]}/_permguard"
```

## In this section

<div class="pgx-link-grid">
  <a href="./command-line/configuration"><strong>Configuration</strong><span>flags · environment · config file · exit codes</span></a>
  <a href="./command-line/workspaces"><strong>Workspaces &amp; Policies</strong><span>init → test → plan → apply</span></a>
  <a href="./command-line/zones-and-ledgers"><strong>Zones &amp; Ledgers</strong><span>create · archive · export · import</span></a>
  <a href="./command-line/decisions"><strong>Decisions &amp; Evidence</strong><span>check · read · export · verify</span></a>
  <a href="./command-line/authority"><strong>Authority</strong><span>accounts · scopes · keys · tokens</span></a>
  <a href="./command-line/operations"><strong>Server Operations</strong><span>discover · host · restore · migrate</span></a>
</div>

<nav class="pgx-pager pgx-pager--next-only" aria-label="Documentation pages">
  <a class="pgx-pager__next" href="./command-line/configuration"><span>Next</span><strong>Configuration <b aria-hidden="true">→</b></strong></a>
</nav>
