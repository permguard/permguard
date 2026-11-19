---
pageClass: pg-page-concepts
title: Workspaces & Policies
description: Create a workspace, prove its policies offline, publish them to a ledger and keep it in sync with the permguard CLI.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero pgx-cli-hero">
  <div class="pgx-kicker">Command Line</div>
  <h1>Author, prove, publish, pull.</h1>
  <p>A workspace is a folder of policy files on your machine, bound to one ledger on a Control Plane.</p>
</div>

You write policies as files in a workspace, check and test them offline, and publish them as one signed commit to a ledger.
The workspace keeps its own state and a local copy of the ledger's objects in `.permguard/`, so most commands here run without a server.
Only `clone`, `checkout`, `pull`, `apply`, `verify` and `test --remote` reach a Plane.

## A typical workflow

<div class="pgx-cli-steps" role="img" aria-label="The workspace workflow: init creates the workspace, validate and test prove it offline, checkout binds it to a ledger, plan shows the change, and apply publishes it as a signed commit.">
  <article><b>01</b><strong>Create</strong><span><code>init</code></span></article>
  <article><b>02</b><strong>Prove offline</strong><span><code>validate</code> · <code>test</code></span></article>
  <article><b>03</b><strong>Bind</strong><span><code>checkout</code></span></article>
  <article><b>04</b><strong>Review</strong><span><code>plan</code></span></article>
  <article class="pgx-cli-steps__accent"><b>05</b><strong>Publish</strong><span><code>apply</code></span></article>
</div>

```sh
permguard -w ./policies init quickstart --language cedar
permguard -w ./policies validate
permguard -w ./policies test

permguard zones create quickstart
permguard ledgers create policies --zone quickstart
permguard -w ./policies remote add origin http://127.0.0.1:6443
permguard -w ./policies checkout origin/quickstart/policies
permguard -w ./policies plan
permguard -w ./policies apply -m "first policy"
```

The steps nest: `validate` runs `refresh` first, `plan` runs `validate`, and `apply` runs `plan` before it pushes.
[Getting Started](../how-it-works/getting-started) runs this flow end to end with a policy, a request and a test case.

## init

Initializes a workspace in the working directory.

```sh
permguard init [OPTIONS] [NAME]
```

| Argument or flag        | Meaning                                                             |
| ----------------------- | ------------------------------------------------------------------- |
| `[NAME]`                | the workspace name written into the manifest; `permguard-workspace` |
| `--language <LANGUAGE>` | the languages to author in, comma separated; `cedar` by default     |

```sh
permguard init release-pipeline --language cedar,rego
```

`init` also writes `.permguardignore`, the list of files and folders no build reads, read as `.gitignore` reads its patterns.
It starts with `requests/` and `tests/` among them, and a workspace starts on the ref `main`.

## remote

Manages the named Control Planes a workspace knows.

```sh
permguard remote add [OPTIONS] <NAME> <URL>
permguard remote list [OPTIONS]
permguard remote remove [OPTIONS] <NAME>
```

| Command         | What it does                                                          |
| --------------- | --------------------------------------------------------------------- |
| `remote add`    | adds, or replaces, a remote reached at `https://host[:port][/prefix]` |
| `remote list`   | lists the remotes                                                     |
| `remote remove` | removes a remote by name                                              |

```sh
permguard remote add origin https://permguard.internal:6443
permguard remote list -o json | jq '.remotes[].name'
```

`pull`, `apply` and `verify` go to the remote the tracked ledger names.
When the workspace no longer knows that remote, they go to the configured `--control-endpoint` instead, and `remote remove` warns you of it.

## clone and checkout

`clone` copies a remote ledger into a new workspace directory; `checkout` binds the current workspace to a ledger and materializes it.

```sh
permguard clone [OPTIONS] <URL> [DIRECTORY]
permguard checkout [OPTIONS] <REFERENCE>
```

| Argument      | Meaning                                                                |
| ------------- | ---------------------------------------------------------------------- |
| `<URL>`       | `clone`: the ledger, as `https://host[:port][/prefix]/<zone>/<ledger>` |
| `[DIRECTORY]` | `clone`: where to clone; the ledger name by default                    |
| `<REFERENCE>` | `checkout`: the ledger, as `<remote>/<zone>/<ledger>[@<ref>]`          |

```sh
permguard clone https://permguard.internal:6443/delivery/release-pipeline ./release-pipeline
permguard checkout origin/delivery/release-pipeline@main
```

## refresh and validate

`refresh` scans the sources and builds the local snapshot; `validate` is `refresh` plus every local check: the manifest, the identities and duplicates.

```sh
permguard refresh [OPTIONS]
permguard validate [OPTIONS]
```

```sh
permguard validate
permguard refresh -o json | jq '.root'
```

With `workspace.one_policy_per_file` set to `true`, the build refuses a policy file that holds more than one policy; see [Configuration](./configuration#the-configuration-file).

## test

Checks that the policies decide what the test cases say they decide, offline, with the same engines a Data Plane runs.

```sh
permguard test [OPTIONS] [PATH]...
```

| Argument or flag      | Meaning                                                                     |
| --------------------- | --------------------------------------------------------------------------- |
| `[PATH]...`           | the case files or folders to run; the workspace's `tests` folder by default |
| `--name <PATTERN>`    | only the cases whose name contains this text                                |
| `--profile <PROFILE>` | asks every case under this profile, whatever its request names              |
| `--list`              | lists the cases and what they expect, and decides nothing                   |
| `--remote`            | asks the tracked Data Plane instead of deciding here                        |
| `--zone <ZONE>`       | the zone to ask, overriding the workspace                                   |
| `--ledger <LEDGER>`   | the ledger to ask, overriding the workspace                                 |

```sh
permguard test
permguard test tests/release.yml
permguard test --name separation -v
permguard test -o json | jq '.failed'
```

A run with a failing case exits 2, so a pipeline stops on it.

## plan and apply

`plan` shows what `apply` would change, the working tree against the tracked head, offline.
`apply` plans, then pushes the change to the remote ledger as one commit.

```sh
permguard plan [OPTIONS]
permguard apply [OPTIONS]
```

| Flag                      | Meaning                                                      |
| ------------------------- | ------------------------------------------------------------ |
| `-m, --message <MESSAGE>` | `apply`: the commit message, never empty; `apply` by default |

```sh
permguard plan
permguard apply -m "require a signed artifact before approval"
```

## pull

Fetches the latest changes of the tracked ledger, verifies them, and lands them in the working tree.

```sh
permguard pull [OPTIONS]
```

| Flag         | Meaning                                                                                                        |
| ------------ | -------------------------------------------------------------------------------------------------------------- |
| `--resolved` | accepts the working tree as already reconciled with the incoming head: use it after merging a conflict by hand |

```sh
permguard pull -v
permguard pull --resolved
```

Without `--resolved`, a file changed both locally and in the incoming head is refused rather than overwritten.

## status and history

`status` shows what the workspace tracks and where it stands, offline; `history` shows the commit history of the tracked ref, newest first.

```sh
permguard status [OPTIONS]
permguard history [OPTIONS]
```

| Flag          | Meaning                                                          |
| ------------- | ---------------------------------------------------------------- |
| `--limit <N>` | `history`: at most this many commits; the whole chain by default |

```sh
permguard status
permguard history --limit 5
permguard history -o json | jq '.commits[].commit'
```

## verify

Verifies the remote head statement and the local closure: the objects the head reaches.

```sh
permguard verify [OPTIONS]
```

```sh
permguard verify -o json
```

A head or closure that does not verify exits 2.

## objects

Inspects the local object store, where every object is named by its digest.

```sh
permguard objects list [OPTIONS]
permguard objects prune [OPTIONS]
permguard objects cat [OPTIONS] <DIGEST>
```

| Command         | What it does                                                                                      |
| --------------- | ------------------------------------------------------------------------------------------------- |
| `objects list`  | lists every object, its kind, and who reaches it                                                  |
| `objects prune` | removes objects nothing reaches: an interrupted pull, a snapshot nobody applied, a passed version |
| `objects cat`   | prints one object; by default a blob's content                                                    |

| Flag        | Meaning                                                             |
| ----------- | ------------------------------------------------------------------- |
| `--tracked` | `list`: only objects reachable from the tracked remote head         |
| `--staged`  | `list`: only objects reachable from the staged snapshot             |
| `--dry-run` | `prune`: reports what would go, and removes nothing                 |
| `--raw`     | `cat`: the exact stored bytes, canonical CBOR, for piping           |
| `--content` | `cat`: a blob's payload, nothing else                               |
| `--inspect` | `cat`: every field, as a structured report                          |
| `--human`   | `cat`: a reading for people: commits like a log, trees as a listing |

```sh
permguard objects list --tracked -o json | jq '.objects[].digest'
permguard objects prune --dry-run
permguard objects cat sha256:0d757bf6828225c716b7b49cda3bde7f5087ca49ed582b85d7ae38ad38e9ee26 --human
```

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./configuration"><span>Previous</span><strong><b aria-hidden="true">←</b> Configuration</strong></a>
  <a class="pgx-pager__next" href="./zones-and-ledgers"><span>Next</span><strong>Zones &amp; Ledgers <b aria-hidden="true">→</b></strong></a>
</nav>
