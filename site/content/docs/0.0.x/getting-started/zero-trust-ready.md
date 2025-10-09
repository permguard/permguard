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
weight: 1003
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** is designed to align with **Zero Trust** principles, leveraging the **ZTAuth*** protocol to provide secure, scalable, and reliable authorization for modern, distributed environments.

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

---

## How Permguard Implements ZTAuth\*

**Permguard** adopts the **ZTAuth*** architecture to bring **Zero Trust** principles into authorization. To understand how this works, let's compare it to network security:

- **ZTNA (Zero Trust Network Access)**: Secures identity-based access to networks by enforcing least privilege at the network boundary.
- **ZTAuth\*** (Zero Trust Auth*): A Zero Trust compliant protocol for secure, identity-based access at the application edge. It supports eventual consistency and resilient synchronization across network disruptions. Built with a delegation-first model, it is ideal for systems that require secure and auditable delegation.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d15.webp"/>
</div><br/>

Looking at the diagram, it is possible to notice the difference between **ZTAuth*** and **Zero Trust Network Access (ZTNA)**.

- **ZTNA** secures network boundaries, controlling access at the network level.
- **ZTAuth*** protects applications, enforcing detailed access control and ensuring consistent security across all actions and resources.

{{< callout context="tip" icon="rocket" >}}
**Asynchronous by Design**: Built to match real-world scenarios, not hide them — reliable where synchronous methods fall short.
{{< /callout >}}

The **ZTAuth*** architecture includes administrative services such as:

- **Zone Administration Point (ZAP)**: Manages zones and related configurations.
- **Policy Administration Point (PAP)**: Defines and manages policies.
- **Policy Information Point (PIP)**: Provides data needed for authorization decisions.
- **Policy Decision Point (PDP)**: Evaluates policies and makes decisions.
- **Policy Enforcement Point (PEP)**: Enforces the decisions made by the PDP.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d5.webp"/>
</div>

However, **ZTAuth\*** introduces a key difference: it defines **Auth*** models that can be transferred to `Proximity` nodes.
These models are incrementally synchronized to zone nodes as **git-like commit-based snapshots**.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d16.webp"/>
</div><br/>

To function properly, these models must have the following characteristics:

- **Transferable and Verifiable:** Works seamlessly across systems and environments, with verifiable origins certified by the `AuthZ Server`.
- **Versionable and Immutable:** Ensures integrity, auditability, and backward compatibility for secure and reliable operations.
- **Resilient to Disconnection:** Supports eventual consistency, allowing continued functionality in partially connected or offline environments.

---

## Application Boundaries

**ZTAuth*** is built for `eventual consistency`, making it ideal for environments with partial connectivity or unreliable networks.
Changes are packaged into **versioned, immutable data structures** and distributed asynchronously in incremental updates.

Every resource action at the application boundary is verified against strict, **identity-based security policies**, ensuring alignment with a well-defined authorization schema.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d17.webp"/>
</div>

The **applicative boundary** includes not only APIs exposed to external consumers but also interactions between machines and services within an application ecosystem. These interactions can use different protocols and technologies, including synchronous requests, asynchronous messaging, and event-driven architectures. **ZTAuth*** ensures that security policies are consistently enforced across all these communication methods.

Today, the applicative boundary extends beyond traditional ingress APIs. It also includes:

- Event streaming
- Messaging systems
- AI agents
- IoT sensors

and many other technologies that interact within and beyond the applicative boundary.

In the **ZTAuth*** architecture, each applicative boundary—whether a single microservice or a larger system—has a **Policy Decision Point (PDP)** deployed. Communication between boundaries happens when one requests an action on a resource managed by another. Each request is securely executed using **identity-based policies**, enforcing the **principle of least privilege** at the applicative boundary.

This model makes it easier for different organizations operating across various networks to securely **federate their systems**. Each applicative boundary enforces its own policies while securely communicating with others, providing **scalability and security** for distributed environments.

---

With **Permguard** and **ZTAuth***, authorization is no longer just an extra step—it becomes a core part of modern security.
