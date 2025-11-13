---
title: "Overview"
slug: "Overview"
description: ""
summary: ""
date: 2023-08-20T17:14:43+01:00
lastmod: 2023-08-20T17:14:43+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "overview-24b9ae1383440efb49528d1ecc48ab03"
weight: 1001
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Permguard is a distributed authorization platform built around Zero Trust principles.

The idea is simple: the application boundary must be protected by a security model where trust is never assumed.
Every incoming request must be validated *before* the application processes it.

This applies to synchronous APIs, asynchronous messages, event streams, WebSocket frames, and any other form of inbound interaction.

The authorization call can be triggered either:

- by the **application** itself, or
- by the **network layer** — for example a service mesh, sidecar proxy, gateway, or edge component.

In both cases, the same security model applies: the request (API call, message, event, etc.) is evaluated *before* the action is executed.

Each request carries at least two identities:

- **Self identity** — the identity of the workload executing the action
- **Peer identity** — the identity of the caller (human, machine, or AI agent)

Additional **attestations** can also be included, such as tokens, signed claims, workload proofs, or any other cryptographic evidence contributing to the trust context.

The Permguard data plane receives the full incoming request context (identities, attestations, network metadata, and application attributes) and uses it to build the authorization context.
As part of a distributed enforcement model, the data plane evaluates this context locally using policies and configuration obtained from the Permguard AuthZ Server (control plane).
The Permguard AuthZ Server is responsible for managing and distributing policies, not for making per-request online decisions.
The data plane then enforces the resulting permit/deny decision at the workload boundary before the action is executed.

This provides a consistent and decentralized security model for both API interactions and asynchronous workflows, regardless of whether enforcement happens in the application or inside the service mesh.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d1.webp"/>
</div>
</br>

Designed for `cloud-native`, `edge`, and `multi-tenant` environments, **Permguard** can be used in any context — including IoT devices, AI agents, and distributed workloads.
It lets you update authorization policies without changing application code, reducing operational overhead.

Policies are centrally managed in the control plane, while enforcement is distributed.
This allows organizations to apply consistent authorization logic across all services without modifying each one individually, ensuring strong governance with a single point for defining, updating, and auditing policies in real time.

{{< callout context="tip" icon="rocket" >}}
**Permguard** provides strong security with a simple integration model. Its architecture offers flexibility and robustness, whether you’re securing a small application or a large distributed system. Run the control plane, define your policies, and integrate the data plane where you need enforcement — the workflow stays straightforward in every environment.
{{< /callout >}}

**Permguard** can be deployed in any environment: `public or private clouds`, `managed infrastructure`, `Kubernetes`, `serverless` platforms, or even in `partially connected` scenarios where stable connectivity is not guaranteed.
It also fits naturally on `edge nodes` and within `IoT` ecosystems, providing consistent and secure authorization across heterogeneous environments.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d13.webp"/>
</div>

It follows a `Bring Your Own Identity (BYOI)` model, meaning Permguard is **identity-agnostic** on the authentication side:
it consumes whatever identity your system already provides — human, machine, workload, or AI agent — without requiring you to replace or restructure your existing AuthN setup.

{{< callout context="note" icon="info-circle" >}}
The main goal of **Permguard** is to provide a strong authorization platform with built-in tools for trust management and governance.
{{< /callout >}}

The platform is `language-agnostic`, supporting multiple policy languages, starting with [Cedar Policy Language](https://www.cedarpolicy.com/en).
This is essential because policy languages evolve quickly, and teams often prefer different DSLs aligned with their trust and governance models.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d18.webp"/>
</div>

Each policy language is supported through a lightweight abstraction layer that keeps the core model stable while reserving only a minimal set of common keywords.

To enforce access control, applications can use the **SDK** or integrate directly with Permguard’s native **APIs**, depending on their architecture and deployment model.
<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d19.webp"/>
</div>

{{< callout context="note" icon="info-circle" >}}
SDKs are available for multiple programming languages, including **Go**, **Rust**, **Java**, **Node.js**, and **Python**, with more under development.
{{< /callout >}}

This model gives precise control over **who or what** can access **which resources**, while keeping the system flexible and easy to integrate.

- `Who`: *Identities — both users and workloads*
- `Can Access`: *Permissions defined through attached policies*
- `Resources`: *The targets of those permissions*

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d14.webp"/>
</div>
