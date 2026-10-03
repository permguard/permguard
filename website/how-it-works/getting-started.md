---
pageClass: pg-page-concepts
title: Getting Started
description: Create, test, publish and evaluate a Permguard policy in a few minutes.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Getting started</div>
  <h1>Policy to decision.</h1>
  <p>Create one Cedar policy, prove it locally, publish it and ask the Data Plane.</p>
</div>

<div class="pgx-runline" aria-label="The quickstart moves through create, test, publish and decide.">
  <span>Create</span><i></i><span>Test</span><i></i><span>Publish</span><i></i><span>Decide</span>
</div>

You need the [Permguard CLI](./install), Rust 1.97 or newer, and [Task](https://taskfile.dev/).

## 1. Start Permguard

From a clone of the repository, in terminal one:

```sh
task run:all
```

This starts one Server with the Host on `:5443`, Control Plane on `:6443` and Data Plane on `:7443`.

## 2. Create a workspace

In terminal two:

```sh
mkdir -p /tmp/permguard-quickstart
permguard -w /tmp/permguard-quickstart init quickstart --language cedar
mkdir -p /tmp/permguard-quickstart/requests /tmp/permguard-quickstart/tests
```

Create the policy:

```sh
cat > /tmp/permguard-quickstart/cedar/documents.cedar <<'CEDAR'
@alias("alice-can-read")
permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Document::"budget"
);
CEDAR
```

Create a request:

```sh
cat > /tmp/permguard-quickstart/requests/permit.json <<'JSON'
{
  "subject": { "type": "User", "id": "alice" },
  "action": { "name": "read" },
  "resource": { "type": "Document", "id": "budget" },
  "context": {}
}
JSON
```

Create the expectation and keep support files outside the policy tree:

```sh
cat > /tmp/permguard-quickstart/tests/quickstart.yml <<'YAML'
- name: Alice can read the budget
  request: ../requests/permit.json
  expect: { decision: permit, policies: [alice-can-read] }
YAML

printf 'requests/\ntests/\n' >> /tmp/permguard-quickstart/.permguardignore
```

## 3. Prove it locally

```sh
permguard -w /tmp/permguard-quickstart validate
permguard -w /tmp/permguard-quickstart test
```

The test uses the same Cedar engine and decision algebra as the Data Plane. No server is involved yet.

## 4. Publish it

```sh
permguard zones create quickstart
permguard ledgers create policies --zone quickstart

permguard -w /tmp/permguard-quickstart remote add origin http://127.0.0.1:6443
permguard -w /tmp/permguard-quickstart checkout origin/quickstart/policies
permguard -w /tmp/permguard-quickstart plan
permguard -w /tmp/permguard-quickstart apply -m "first policy"
```

`apply` uploads missing content-addressed objects and advances the signed ledger head.

## 5. Ask the Data Plane

With the CLI:

```sh
permguard -w /tmp/permguard-quickstart check \
  -f /tmp/permguard-quickstart/requests/permit.json
```

Or call the discovered HTTP endpoint directly:

```sh
jq '. + {zone: "quickstart", ledger: "policies"}' \
  /tmp/permguard-quickstart/requests/permit.json |
curl -sS -X POST http://127.0.0.1:7443/access/v1/evaluation \
  -H 'content-type: application/json' \
  -H 'x-request-id: quickstart-1' \
  --data-binary @- | jq
```

<div class="pgx-outcome"><span>permit</span><p>The answer names the policy version and carries a decision identity that can be joined to its evidence.</p></div>

This quickstart uses the remote HTTP PDP to make the wire contract visible. Production placement is not constrained to a network service: the same decision capability can run embedded, as a sidecar or behind a remote API.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./container-images"><span>Previous</span><strong><b aria-hidden="true">←</b> Container Images</strong></a>
  <a class="pgx-pager__next" href="./architecture"><span>Next</span><strong>Server, Host &amp; Planes <b aria-hidden="true">→</b></strong></a>
</nav>
