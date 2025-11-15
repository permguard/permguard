---
title: "Zero Trust Alignment"
slug: "Zero Trust Alignment"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "zero-trust-ready-8c89ddc8339f83444fc4b97264bd5c45"
weight: 1006
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** is designed to align with **Zero Trust** principles, leveraging the **ZTAuth\*** protocol to provide secure, scalable, and reliable authorization for modern, distributed environments.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/ztauth.webp"/>
</div>

{{< callout context="tip" icon="rocket" >}}
**Permguard** is powerful yet easy to use. Its advanced architecture ensures security and flexibility, while integration remains simple—whether for a basic app or a complex enterprise system. Just run the server, define your policy, and integrate it seamlessly.
{{< /callout >}}

---

## Three Core Principles of Zero Trust

1. **Never Trust, Always Verify**
   Every access request, no matter its origin or previous validation, must be verified before access is granted. This ensures that trust is never assumed but continuously validated.

2. **Enforce Least Privilege Access**
   Users, services, and devices should only access the resources needed for their tasks. This reduces the risk of unauthorized actions and potential security breaches.

3. **Assume Breach**
   Design systems with the expectation that a breach can and will happen. This approach ensures strong security measures to limit damage and maintain resilience even if compromised.

In addition to the three core principles, `network segmentation` is a foundational requirement for advancing Zero Trust security.
By dividing the environment into **small, isolated zones**—each with its own **access controls** and **enforcement boundaries**—you limit lateral movement and ensure that **every request is treated as untrusted** until explicitly validated.

---

## How Permguard Implements Zero Trust

**Permguard** adopts the [**ZTAuth\***](https://spec.ztauthstar.com/openprotocolspec/) architecture to bring **Zero Trust** principles into authorization. To understand how this works, let's compare it to network security:

- **ZTNA (Zero Trust Network Access)**: Secures identity-based access to networks by enforcing least privilege at the network boundary.
- **ZTAuth\*** (Zero Trust Auth*): A Zero Trust compliant protocol for secure, identity-based access at the application edge. It supports eventual consistency and resilient synchronization across network disruptions. Built with a delegation-first model, it is ideal for systems that require secure and auditable delegation.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d15.webp"/>
</div>
<br/>

**ZTAuth\*** and **Zero Trust Network Access (ZTNA)** are not the same:

- **ZTNA** secures network boundaries, controlling access at the network level.
- **ZTAuth\*** protects applications, enforcing detailed access control and ensuring consistent security across all actions and resources.

{{< callout context="tip" icon="rocket" >}}
**Asynchronous by Design**: Built to match real-world scenarios, not hide them — reliable where synchronous methods fall short.
{{< /callout >}}

The **Permguard** architecture includes administrative services such as:

- **Zone Administration Point (ZAP)**: Manages zones and related configurations.
- **Policy Administration Point (PAP)**: Defines and manages policies.
- **Policy Information Point (PIP)**: Provides data needed for authorization decisions.
- **Policy Decision Point (PDP)**: Evaluates policies and makes decisions.
- **Policy Enforcement Point (PEP)**: Enforces the decisions made by the PDP.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d5.webp"/>
</div>

**ZTAuth\*** introduces a key difference: it defines **Auth*** models that can be transferred to `Proximity data planes`.
These models are incrementally synchronized to zone nodes as **git-like commit-based snapshots**.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d16.webp"/>
</div><br/>

To function properly, these models must have the following characteristics:

- **Transferable and Verifiable:** Works seamlessly across systems and environments, with verifiable origins certified by the `AuthZ Server`.
- **Versionable and Immutable:** Ensures integrity, auditability, and backward compatibility for secure and reliable operations.
- **Resilient to Disconnection:** Supports eventual consistency, allowing continued functionality in partially connected or offline environments.

---

## ZTAuth\* Architectural Model

The **ZTAuth\*** architectural model defines how trust is established, transported, evaluated, and governed across distributed systems.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d17.webp"/>
</div>

This model is composed of five layers that work together to produce verifiable, Zero Trust–aligned authorization decisions:

- **Trusted Input** — the initial cryptographic material (credentials, tokens, attestations) that identifies who or what is requesting an action.
- **Trusted Channel** — the secure transport that ensures confidentiality, integrity, and authenticated communication between components.
- **Autonomous Component** — the workload executing the action, enforcing decisions close to where they matter.
- **Policy Decision Point (PDP)** — the logic that evaluates context and policies to compute a permit/deny decision.
- **Trust Governance** — the control plane that defines, distributes, and audits policies and trust relationships.

<br/>
<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/ztauthstart-architecture.png"/>
</div>
<br/>

Together, these layers create a unified authorization model where every decision is **context-aware**, **cryptographically verifiable**, and **aligned with organizational intent**, enabling consistent Zero Trust enforcement across both synchronous and asynchronous boundaries.

For additional details and in-depth semantics, you can refer to the full [**ZTAuth\* specification**](https://spec.ztauthstar.com/openprotocolspec/).

{{< callout context="tip" icon="rocket" >}}
With **Permguard** and **ZTAuth\***, authorization is no longer just an extra step—it becomes a core part of modern security.
{{< /callout >}}
