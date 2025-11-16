---
title: "Intro to Permguard"
slug: "Intro to Permguard"
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
  title: ""
  description: ""
  canonical: ""
  noindex: false
---

## What is Permguard?

**Permguard** is a distributed authorization platform built around Zero Trust principles.

At its core, Permguard defines **who** or **what** can access **which resources** using a unified policy model:

- **Who** — identities (users and workloads)
- **Can Access** — permissions defined through policies
- **Which Resources** — the targets of those permissions

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d14.webp"/>
</div>

## What Permguard Enforces

The fundamental Zero Trust rule in Permguard is simple:
**every incoming request must be validated before the application processes it**.

This applies uniformly across all interaction types — synchronous APIs, asynchronous messages, event streams, WebSocket frames, and cross-service calls — ensuring consistent enforcement at both the network layer and the application layer.

Beyond the input boundary, Permguard also governs **in-code authorization policies**, allowing applications to perform fine-grained checks at critical points:

- before calling a domain service
- before executing a sensitive command
- before accessing or mutating data

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d1.webp"/>
</div>
</br>

The same policy model is applied across all enforcement layers, ensuring authorization remains:

- **governed in intent** — rules are collaboratively reviewed, versioned, and managed
- **decentralized in enforcement** — decisions occur close to where actions happen
- **auditable and explainable** — full end-to-end visibility across the authorization path

## Centralized Interface, Decentralized Architecture

Policies are accessed through a unified control-plane interface, but this does **not** imply a centralized trust model.

- The current implementation uses a single access endpoint for simplicity
- The architecture already supports **decentralized consensus** behind that interface

Enforcement remains distributed, while the control-plane provides a coherent place to define, review, update, and audit policies.

{{< callout context="tip" icon="rocket" >}}
**Permguard** offers strong Zero Trust security with a simple integration path — define authorization intent once and enforce it everywhere.
{{< /callout >}}

## Bring Your Own Identity (BYOI)

Permguard is **identity-agnostic** on the authentication side.
It follows a `Bring Your Own Identity (BYOI)` approach:

- it consumes any identity your system already provides
- it supports both user and workload identities
- it does not replace your existing AuthN layer

{{< callout context="note" icon="info-circle" >}}
The main goal of **Permguard** is to provide strong authorization with built-in trust governance, not authentication.
{{< /callout >}}

## Where Authorization Runs

Authorization can be triggered by either:

- **Network Layer**
e.g., service mesh, sidecar proxy, gateway, or edge component.

- **Application Layer**
via SDKs or native APIs.

In both cases, the request is always evaluated **before** performing any action.

Each incoming request carries at least two identities:

- **Self identity** — the workload performing the action
- **Peer identity** — the caller (user or workload)

Additional **attestations** may also be included, such as tokens, workload proofs, or signed claims.

---

The **data-plane** receives the full request context (identities, attestations, network metadata, application attributes) and evaluates it locally using policies obtained from the **control-plane**.

- The **control-plane** manages and distributes policies
- The **data-plane** enforces permit/deny decisions at the workload boundary

This creates a consistent and decentralized Zero Trust model for both synchronous and asynchronous workflows.

---

Designed for `cloud-native`, `edge`, and `multi-tenant` environments, Permguard enables updating policies without changing application code.

---

## Policy Languages

Permguard is `language-agnostic` and supports multiple policy languages, starting with **Cedar**:

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d18.webp"/>
</div>

Each language is implemented through a thin abstraction layer that keeps the core model stable while requiring only a minimal common keyword set.

---

## Deployment Flexibility

Permguard can run in:

- `on-premises`, `private`, or `public` cloud environments
- `Kubernetes` and `serverless` platforms
- `edge` and `IoT` ecosystems, including `partially connected` or `disconnected` scenarios

The architecture consists of two main components:

- `Control Plane`
Must be reachable at the network level to expose policy governance.
It can also run on `edge` components or distributed infrastructure as long as it provides a consistent governance view.

- `Data Planes`
Can be deployed anywhere — inside applications, gateways, edge devices, remote regions, or disconnected environments.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d13.webp"/>
</div>

---

## Integrating with Permguard

Applications can enforce access control using:

- the official **SDKs**, or
- Permguard’s native **APIs**

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d19.webp"/>
</div>

{{< callout context="note" icon="info-circle" >}}
SDKs are available for **Go**, **Rust**, **Java**, **.NET Core**, **Node.js**, and **Python**, with more in development.
{{< /callout >}}

---

## Summary

Permguard provides:

- Strong Zero Trust authorization
- Distributed enforcement
- Centralized governance of intent
- Integration at network or application layers
- Support for multiple identity systems
- Language-agnostic policy definitions
- Flexible deployment across clouds, edge, and IoT

Together, these capabilities provide precise control over **who** can access **which resources**, with consistent security across heterogeneous environments.
