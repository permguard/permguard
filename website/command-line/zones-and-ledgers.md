---
pageClass: pg-page-concepts
title: Zones & Ledgers
description: Create, list, rename, archive, delete, export and import zones and ledgers with the permguard CLI.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero pgx-cli-hero">
  <div class="pgx-kicker">Command Line</div>
  <h1>The catalog, from a terminal.</h1>
  <p>A zone is the isolation boundary everything else lives inside; a ledger is a named container of policy inside a zone.</p>
</div>

The `zones` and `ledgers` commands manage the catalog of a Control Plane, reached at `--control-endpoint`.
Every command takes a zone or a ledger by its name or by its id, and an id never changes when a name does.
[Zones & Ledgers](../how-it-works/zones-and-ledgers) explains the model; this page is the commands.

## Rules every catalog command shares

| Rule         | Meaning                                                                                                                     |
| ------------ | --------------------------------------------------------------------------------------------------------------------------- |
| zone names   | lowercase `a-z`, `0-9`, `-` and `_`, unique across the deployment                                                           |
| ledger names | unique within their zone                                                                                                    |
| revisions    | `--expected-revision <N>` makes a change against that revision; another one on the server refuses it as `revision_conflict` |
| default      | without `--expected-revision`, the change is made against the revision a read just before answers                           |
| paging       | `--page <N>` counts from 0; `--size <N>` is at least 1, server-capped, 100 when only `--page` is given                      |
| archives     | an export is written to a new file, readable by its owner only                                                              |

## zones

Manages zones.

```sh
permguard zones create [OPTIONS] <NAME>
permguard zones list [OPTIONS]
permguard zones get [OPTIONS] <ZONE>
permguard zones update [OPTIONS] --name <NAME> <ZONE>
permguard zones delete [OPTIONS] <ZONE>
permguard zones export [OPTIONS] --out <FILE> <ZONE>
permguard zones import [OPTIONS] --as <ZONE> --mode <MODE> --bundle <FILE> --pin <PIN> <FILE>
```

| Command        | What it does                                                                                       |
| -------------- | -------------------------------------------------------------------------------------------------- |
| `zones create` | creates a zone                                                                                     |
| `zones list`   | lists the zones, every one or a page at a time                                                     |
| `zones get`    | shows one zone                                                                                     |
| `zones update` | renames a zone with `--name`; the id never changes                                                 |
| `zones delete` | deletes a zone; refused while it still holds ledgers                                               |
| `zones export` | exports every ledger of a zone: the signed archive the plane's Host answers                        |
| `zones import` | imports an archive another Host exported into an existing zone, every ledger under its source name |

```sh
permguard zones create delivery
permguard zones list --page 2 --size 50
permguard zones list -o json | jq '.zones[].name'
permguard zones update delivery --name delivery-eu
permguard zones export delivery --out delivery.export
```

## ledgers

Manages the ledgers of a zone; every command names the zone with `--zone`, except `import`, which names it in `--as`.

```sh
permguard ledgers create [OPTIONS] --zone <ZONE> <NAME>
permguard ledgers list [OPTIONS] --zone <ZONE>
permguard ledgers get [OPTIONS] --zone <ZONE> <LEDGER>
permguard ledgers update [OPTIONS] --zone <ZONE> --name <NAME> <LEDGER>
permguard ledgers archive [OPTIONS] --zone <ZONE> <LEDGER>
permguard ledgers restore [OPTIONS] --zone <ZONE> <LEDGER>
permguard ledgers delete [OPTIONS] --zone <ZONE> <LEDGER>
permguard ledgers export [OPTIONS] --zone <ZONE> --out <FILE> <LEDGER>
permguard ledgers import [OPTIONS] --as <ZONE/NAME> --mode <MODE> --bundle <FILE> --pin <PIN> <FILE>
```

| Command           | What it does                                                                                              |
| ----------------- | --------------------------------------------------------------------------------------------------------- |
| `ledgers create`  | creates a ledger inside a zone                                                                            |
| `ledgers list`    | lists a zone's ledgers, every one or a page at a time                                                     |
| `ledgers get`     | shows one ledger                                                                                          |
| `ledgers update`  | renames a ledger with `--name`; the id never changes                                                      |
| `ledgers archive` | archives a ledger: it stays readable and mirrored, and takes no push until restored                       |
| `ledgers restore` | restores an archived ledger: it takes pushes again                                                        |
| `ledgers delete`  | deletes a ledger                                                                                          |
| `ledgers export`  | exports a ledger: the signed archive the plane's Host answers                                             |
| `ledgers import`  | imports a one-ledger archive another Host exported, as `<zone>/<name>`: the zone exists, the name is free |

```sh
permguard ledgers create --zone delivery release-pipeline
permguard ledgers list --zone delivery -o json | jq '.ledgers[].id'
permguard ledgers archive --zone delivery release-pipeline --expected-revision 3
permguard ledgers restore --zone delivery release-pipeline
permguard ledgers export --zone delivery release-pipeline --out release.export
```

## Moving ledgers between Hosts

An export is the signed archive the source plane's Host answers.
An import names that Host's keys bundle and identity pin, and lands the archive in one of two modes.

| Flag              | Meaning                                                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------- |
| `<FILE>`          | the archive file an export wrote                                                                    |
| `--as`            | `zones import`: the existing zone to import into; `ledgers import`: `<zone>/<name>`, where it lands |
| `--mode archive`  | keeps the archive as foreign evidence, never served                                                 |
| `--mode re-home`  | creates new ledgers under this Host, serving once an operator pushes a head                         |
| `--bundle <FILE>` | the source Host's keys bundle: `{"manifest": "<base64url>", "items": ["<base64url>", …]}`           |
| `--pin <PIN>`     | the source Host's identity pin                                                                      |

```sh
permguard ledgers import release.export --as delivery/release \
  --mode re-home --bundle source.bundle --pin sha256:…
permguard zones import delivery.export --as evidence \
  --mode archive --bundle source.bundle --pin sha256:…
```

`permguard host keys bundle export` writes a bundle in the shape `--bundle` reads; see [Server Operations](./operations#host-keys).

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./workspaces"><span>Previous</span><strong><b aria-hidden="true">←</b> Workspaces &amp; Policies</strong></a>
  <a class="pgx-pager__next" href="./decisions"><span>Next</span><strong>Decisions &amp; Evidence <b aria-hidden="true">→</b></strong></a>
</nav>
