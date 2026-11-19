---
pageClass: pg-page-concepts
title: Container Images
description: Pull versioned Permguard images from GHCR or Docker Hub and verify their provenance.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Container images</div>
  <h1>Same release. Two registries.</h1>
  <p>Run the complete server, one plane or the CLI on Linux AMD64 and ARM64.</p>
</div>

<div class="pgx-registry-flow" role="img" aria-label="One Permguard release builds five images once and pushes them, with the same tags and the same digests, to GitHub Container Registry and Docker Hub.">
  <article class="pgx-registry-flow__release"><small>RELEASE</small><strong>vX.Y.Z</strong><span>one source commit</span></article>
  <i aria-hidden="true">→</i>
  <div>
    <article><small>DEFAULT</small><strong>GHCR</strong><span>version · major.minor · latest</span></article>
    <article><small>SAME IMAGES</small><strong>Docker Hub</strong><span>version · major.minor · latest</span></article>
  </div>
</div>

## Choose the runtime

<div class="pgx-image-grid">
  <article><small>ALL-IN-ONE</small><strong>Every plane</strong><code>all-in-one</code><span>Authority, Control and Data in one process, for local use or compact deployments.</span></article>
  <article><small>AUTHORITY PLANE</small><strong>Issue tokens</strong><code>authority-plane</code><span>Identities, access keys and the tokens every Plane verifies.</span></article>
  <article><small>CONTROL PLANE</small><strong>Publish policy</strong><code>control-plane</code><span>Authoritative ledgers and policy distribution.</span></article>
  <article><small>DATA PLANE</small><strong>Make decisions</strong><code>data-plane</code><span>Verified policy close to the workload.</span></article>
  <article><small>COMMAND LINE</small><strong>Automate the CLI</strong><code>cli</code><span>CI jobs and container-native workflows.</span></article>
</div>

## Two registries, one image

Every release is built once and pushed to both registries with the same tags: the version, its `major.minor` line and `latest`.
The digests are identical, so either registry serves the same image.
These docs use GHCR in every example; Docker Hub works the same way under shorter names.
Use an exact version in production.

## Pull from GHCR

```sh
VERSION=0.1.33
docker pull ghcr.io/permguard/permguard/all-in-one:${VERSION}
docker pull ghcr.io/permguard/permguard/authority-plane:${VERSION}
docker pull ghcr.io/permguard/permguard/control-plane:${VERSION}
docker pull ghcr.io/permguard/permguard/data-plane:${VERSION}
docker pull ghcr.io/permguard/permguard/cli:${VERSION}
```

Browse the [Permguard packages on GHCR](https://github.com/orgs/permguard/packages?repo_name=permguard).

## Pull from Docker Hub

The same images, with the same tags and digests, under shorter names.

```sh
VERSION=0.1.33
docker pull permguard/all-in-one:${VERSION}
docker pull permguard/authority-plane:${VERSION}
docker pull permguard/control-plane:${VERSION}
docker pull permguard/data-plane:${VERSION}
docker pull permguard/cli:${VERSION}
```

Browse [Permguard on Docker Hub](https://hub.docker.com/u/permguard).

## Configuration stays explicit

Server images take the same YAML configuration as the release binaries. Start from the maintained examples in the repository:

- [`crates/permguard-all-in-one/config.local.yml`](https://github.com/permguard/permguard/blob/main/crates/permguard-all-in-one/config.local.yml)
- [`crates/permguard-authority-plane/config.docker-tls.yml`](https://github.com/permguard/permguard/blob/main/crates/permguard-authority-plane/config.docker-tls.yml)
- [`crates/permguard-control-plane/config.local.yml`](https://github.com/permguard/permguard/blob/main/crates/permguard-control-plane/config.local.yml)
- [`crates/permguard-data-plane/config.local.yml`](https://github.com/permguard/permguard/blob/main/crates/permguard-data-plane/config.local.yml)
- [`docker/release`](https://github.com/permguard/permguard/tree/main/docker/release) for image entrypoints and paths

## Verify before running

GitHub publishes build provenance for release images. Verify the exact image you will deploy:

```sh
gh attestation verify \
  oci://ghcr.io/permguard/permguard/all-in-one:0.1.33 \
  --repo permguard/permguard
```

<div class="pgx-note"><strong>Pin the version.</strong><span>A tag such as <code>0.1.33</code> is readable; a digest is the immutable deployment identity.</span></div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./install"><span>Previous</span><strong><b aria-hidden="true">←</b> Install</strong></a>
  <a class="pgx-pager__next" href="./getting-started"><span>Next</span><strong>Getting Started <b aria-hidden="true">→</b></strong></a>
</nav>
