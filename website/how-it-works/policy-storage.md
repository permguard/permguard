---
pageClass: pg-page-concepts
title: Git-like Versioning
description: Policy files become content-addressed objects, immutable commits and a signed, append-only history.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Git-like versioning</div>
  <h1>Policy has history.</h1>
  <p>Every version is content-addressed. Every publication is signed. Nothing is overwritten.</p>
</div>

<div class="pgx-ledger-stack" role="img" aria-label="Four layers. Files you edit: manifest.yml and cedar/documents.cedar. permguard plan extracts every policy, validates it and hashes it into content-addressed objects: a root tree holding the manifest blob and a cedar tree, which holds one blob per policy. permguard apply wraps the root tree in commit C3, whose parent is C2, whose parent is C1. The Control Plane accepts C3, moves refs/main to it at counter 3 and signs a head statement.">
  <section class="pgx-ledger-stack__layer">
    <header><small>01 · FILES</small><strong>What you edit</strong></header>
    <div class="pgx-ledger-stack__items">
      <span class="pgx-ledger-stack__item"><em>manifest</em><code>manifest.yml</code></span>
      <span class="pgx-ledger-stack__item"><em>policy source</em><code>cedar/documents.cedar</code></span>
    </div>
  </section>
  <div class="pgx-ledger-stack__step"><b aria-hidden="true">↓</b><span><code>plan</code> extracts every policy, validates, hashes</span></div>
  <section class="pgx-ledger-stack__layer">
    <header><small>02 · OBJECTS</small><strong>Content-addressed</strong></header>
    <div class="pgx-ledger-stack__items">
      <span class="pgx-ledger-stack__item"><em>tree · root</em><span>sha256:91c4…</span></span>
      <span class="pgx-ledger-stack__item"><em>blob</em><code>manifest</code><span>sha256:3e07…</span></span>
      <span class="pgx-ledger-stack__item"><em>tree</em><code>cedar</code><span>sha256:b81d…</span></span>
      <span class="pgx-ledger-stack__item"><em>blob · one policy</em><code>alice-can-read.cedar</code><span>sha256:7a19…</span></span>
    </div>
  </section>
  <div class="pgx-ledger-stack__step"><b aria-hidden="true">↓</b><span><code>apply</code> commits the root tree and pushes what is missing</span></div>
  <section class="pgx-ledger-stack__layer">
    <header><small>03 · COMMITS</small><strong>Immutable, parent-linked</strong></header>
    <div class="pgx-ledger-stack__items pgx-ledger-stack__chain">
      <span class="pgx-ledger-stack__item"><em>C1 · history root</em><span>sha256:8f10…</span></span>
      <i aria-hidden="true">←</i>
      <span class="pgx-ledger-stack__item"><em>C2 · parent C1</em><span>sha256:a36f…</span></span>
      <i aria-hidden="true">←</i>
      <span class="pgx-ledger-stack__item pgx-ledger-stack__item--current"><em>C3 · parent C2</em><span>sha256:4b2e…</span></span>
    </div>
  </section>
  <div class="pgx-ledger-stack__step"><b aria-hidden="true">↓</b><span>the Control Plane verifies, advances the ref, signs</span></div>
  <section class="pgx-ledger-stack__layer pgx-ledger-stack__layer--published">
    <header><small>04 · PUBLISHED</small><strong>Signed head</strong></header>
    <div class="pgx-ledger-stack__items">
      <span class="pgx-ledger-stack__item"><em>ref</em><code>refs/main → C3</code></span>
      <span class="pgx-ledger-stack__item"><em>counter</em><code>3</code></span>
      <span class="pgx-ledger-stack__item pgx-ledger-stack__item--current"><em>head statement</em><code>COSE_Sign1</code><span>Ed25519 or P-256</span></span>
    </div>
  </section>
</div>

## The model

| Object         | Holds                                                     | Changes                           |
| -------------- | --------------------------------------------------------- | --------------------------------- |
| blob           | One policy, a schema or the manifest, with its media type | Never: new bytes, new digest      |
| tree           | Sorted entries: name, kind, digest, policy id, alias      | Never                             |
| commit         | Root tree, manifest, parents, author, date, message       | Never                             |
| ref            | One name, `main`, pointing at one commit, with a counter  | Forward only, by compare-and-swap |
| head statement | Ref, head, counter, ref digest, authority, signing ring   | A new one for every accepted head |

A digest is `sha256:` over the object's canonical CBOR, so every party computes the same one and non-canonical bytes are refused.

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card"><span>Granularity</span><h3>One policy, one blob</h3><p>The CLI splits each source file into its policies and stores each as <code>&lt;alias|id&gt;.&lt;ext&gt;</code>. Files are how you write; policies are what is versioned.</p></article>
  <article class="pgx-card"><span>Identity</span><h3>Ids survive edits</h3><p>A policy keeps its id by path, then by <code>@alias</code> across a rename; a new one gets a UUIDv8 derived from its bytes.</p></article>
  <article class="pgx-card pgx-card--accent"><span>Portability</span><h3>Same id on every OS</h3><p>Line endings are normalised to <code>\n</code> before hashing: a Windows checkout and a Linux checkout produce identical objects.</p></article>
</div>

## The workflow

```sh
permguard init quickstart --language cedar
# every local check, offline
permguard validate
permguard remote add origin http://127.0.0.1:6443
permguard checkout origin/quickstart/policies
# the working tree against the tracked head, offline
permguard plan
# commit, then push
permguard apply -m "first policy"
# newest first
permguard history
# fetch, verify, land in the working tree
permguard pull
```

Edit the policy, then plan and apply the change.
Digests are shortened here; the CLI prints them whole.

```txt
$ permguard plan
The following changes would be applied:

  ~ cedar/alice-can-read.cedar  5f1c2a9e-7b3d-8e41-9a6c-2d8e0f4b7a13

Plan: 0 to create, 1 to update, 0 to delete (0 unchanged).

$ permguard apply -m "budget: read-only for alice"
  ~ cedar/alice-can-read.cedar  5f1c2a9e-7b3d-8e41-9a6c-2d8e0f4b7a13

Apply complete. Ref `main` advanced to counter 2 — 4 objects uploaded.
  head sha256:a36f…

$ permguard history
commit sha256:a36f…
Author: alice
Date:   2026-11-19T09:42:07Z

    budget: read-only for alice

commit sha256:8f10…
Author: alice
Date:   2026-11-18T16:05:31Z

    first policy
```

One edited policy uploaded four objects: its blob, its partition tree, the root tree and the commit.
The manifest did not change, so it did not travel.

| Command                                     | What it does                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------- |
| `init [NAME] --language cedar,rego`         | Creates a workspace and writes its manifest                               |
| `validate`                                  | Builds the snapshot and runs every local check: manifest, ids, duplicates |
| `plan`                                      | Compares the working tree with the tracked head, offline                  |
| `apply -m "<message>"`                      | Plans, commits and pushes; the message cannot be empty                    |
| `history [--limit N]`                       | Lists the commits of the tracked ref, newest first                        |
| `checkout <remote>/<zone>/<ledger>[@<ref>]` | Binds the workspace to a ledger and materialises it                       |
| `clone <url> [DIRECTORY]`                   | Checks a ledger out into a fresh directory                                |
| `pull [--resolved]`                         | Fetches, verifies and lands the latest head in the working tree           |
| `status`                                    | Shows the tracked ref, its counter and what is pending, offline           |
| `objects list` · `objects cat <digest>`     | Inspects the local object store; `--human` reads a commit like a log      |

`pull` refuses files changed on both sides.
Reconcile them by hand, then `pull --resolved` lands the rest and advances.

## History is append-only

<div class="pgx-history-flow" role="img" aria-label="Three immutable parent-linked commits. C1 has no parent and was accepted at counter 1. C2 names C1 as its parent, counter 2. C3 names C2, counter 3, and is where refs/main points.">
  <article><small>COMMIT C1</small><strong>First policy</strong><code>8f10… · no parent</code><span>counter 1</span></article>
  <i>→</i>
  <article><small>COMMIT C2</small><strong>Read-only budget</strong><code>a36f… · parent C1</code><span>counter 2</span></article>
  <i>→</i>
  <article class="pgx-history-flow__current"><small>COMMIT C3</small><strong>Add contractors</strong><code>4b2e… · parent C2</code><span>counter 3 · refs/main</span></article>
</div>

A commit never changes.
The ref is the only thing that moves, and only forward: the Control Plane refuses a new head that does not descend from the current one (`not_fast_forward`), and a push that expected a ref state that is no longer current (`ref_conflict`).
Each accepted move raises the counter by one, records the digest of the previous ref state, and produces a signed head statement.

<div class="pgx-integrity-strip">
  <article><strong>Same digest, different bytes</strong><span>corruption</span></article>
  <article><strong>Lower counter than last seen</strong><span>rollback</span></article>
  <article><strong>Same counter, different state</strong><span>equivocation</span></article>
</div>

Every client keeps the last counter and ref digest it accepted, and refuses all three.
Run `permguard verify` to check the signed head against the key ring, the counter against rollback and equivocation, and the local closure hash by hash.

## Git-like, not Git

| Aspect               | Git                               | Permguard                                                           |
| -------------------- | --------------------------------- | ------------------------------------------------------------------- |
| Objects              | blob, tree, commit                | Same, plus a manifest in every commit                               |
| History              | Immutable, parent-linked commits  | Same                                                                |
| Identity             | Hash of the stored bytes          | `sha256:` over canonical CBOR; non-canonical bytes refused          |
| A blob is            | Any file                          | One policy, schema or manifest, typed by its media type             |
| Accepting a push     | Any well-formed objects           | Manifest, partitions, schemas and policy ids validated at commit    |
| Moving a ref         | Force push can rewrite it         | Fast-forward only, compare-and-swap on counter and ref digest       |
| Proof of publication | Optional signatures by the author | Every accepted head signed by the Control Plane, with a counter     |
| Transport            | Git protocol over SSH or HTTP     | [NOTP](./notp): CBOR over HTTP and gRPC, discovered from the server |

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./zones-and-ledgers"><span>Previous</span><strong><b aria-hidden="true">←</b> Zones &amp; Ledgers</strong></a>
  <a class="pgx-pager__next" href="./notp"><span>Next</span><strong>NOTP Protocol <b aria-hidden="true">→</b></strong></a>
</nav>
