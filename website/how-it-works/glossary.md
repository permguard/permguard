---
pageClass: pg-page-concepts
title: Glossary
description: Every Permguard term in one line, with the page that explains it.
outline: [2, 3]
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Glossary</div>
  <h1>Every term, in one line.</h1>
  <p>The words these pages use, each with the page that goes deeper.</p>
</div>

## The question

Every authorization question has the same four parts, and one answer.

### Subject {#subject}

Who asks to act: a user, a service or an AI agent, as `User alice`.
Your Identity Provider says who it is; Permguard decides what it may do.
Cedar calls it the principal.

### Action {#action}

What the subject wants to do, as `read`.

### Resource {#resource}

What the action is done on, as `Document budget`.

### Context {#context}

Any other fact the policy reads: the time, the network, a risk score.
When a threat changes, the context changes and the policy stays the same.

### Decision {#decision}

The answer: permit or deny.
Nothing is permitted unless a policy permits it, and the answer names the policy that decided.
See [Decision Lifecycle](./decision-lifecycle).

## The roles

### PEP · Policy Enforcement Point {#pep}

The place in your code that guards an action: it asks before acting, and obeys the answer.
In practice, a call to a Permguard SDK.
When no answer comes, it treats that as a no: fail closed.

### PDP · Policy Decision Point {#pdp}

What answers the question.
In Permguard, the Data Plane: a sidecar beside the application, a remote service, or a library inside the process.

### Trust Anchor {#trust-anchor}

A different family of decision point, planned next in the Data Plane.
It answers a protocol question, whether a hand-off may cross a boundary, so it is not a PDP.
See [Trust Plane](../trust-plane).

### SDK {#sdk}

The client library your PEP calls, for Go, Java, .NET, Node.js, Python and Rust.

## The server

### Server and Host {#host}

A Permguard Server is one process with one Host and the planes you deploy.
The Host owns identity, keys, audit, membership and streams for every plane.
See [Server, Host & Planes](./architecture).

### Control Plane {#control-plane}

Where policies live: in ledgers, versioned like Git, published as signed versions.
Port `6443`.
See [Control Plane](../control-plane).

### Data Plane {#data-plane}

The PDP.
It mirrors and verifies the signed policy before any request, then decides locally and records every decision.
Port `7443`.
See [Data Plane](../data-plane).

### Authority Plane {#authority-plane}

Issues the access tokens with which callers of Permguard itself prove who they are: service accounts, scopes and access keys.
Port `8443`.
See [Authority Plane](./authority-plane).

### Trust Plane {#trust-plane}

Authority continuity along a chain of executions, with the PIC protocol.
In development.
See [Trust Plane](../trust-plane).

## Policies

### Policy {#policy}

A rule in a file, as code, that an execution follows.
Today, application policies: who may do what, on what, under which facts.
See [Policy Lifecycle](./policy-lifecycle).

### Policy language {#policy-language}

Cedar and Rego, side by side in the same ledger; Dogwood, for decisions that depend on history, is experimental.
See [Policy Languages](./policy-languages).

### Zone and ledger {#ledger}

A zone groups ledgers; a ledger holds the versioned history of a set of policies.
Every change is a commit.
See [Git-like Policy Storage](./policy-storage).

### Signed head {#signed-head}

The signed statement that names which commit of a ledger is the accepted version.
A version never changes once published.

## Records

### Decision id {#decision-id}

The identity of one decision, returned in the answer and carried by its record.

### Evidence {#evidence}

The record of every decision: who, what, on which resource, under which policy, permit or deny.
Records are signed and chained, so a change to any of them is detected.
See [Evidence & Verification](./evidence).

## Around Permguard

### Identity Provider {#identity-provider}

Your existing system for who people and services are, as an OpenID Connect provider.
Permguard does not replace it.

### SIEM {#siem}

Your security information and event management system.
Export the decision records to it as JSON Lines or CSV, beside your other security logs.

<nav class="pgx-pager pgx-pager--previous-only" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./policy-languages"><span>Previous</span><strong><b aria-hidden="true">←</b> Policy Languages</strong></a>
</nav>
