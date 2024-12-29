---
title: "Zero Trust Principles"
slug: "Zero Trust Principles"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "zero-trust-principles-8c89ddc8339f83444fc4b97264bd5c45"
weight: 1003
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** is designed with Zero Trust principles at its core, leveraging the **ZTAuth\*** architecture to ensure secure, scalable, and reliable authorization in modern, distributed environments.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/ztauth.png"/>
</div>

{{< callout context="tip" icon="rocket" >}}
Permguard may seem complex, but it’s not: its internal architecture is sophisticated, yet integration is simple—perfect for everything from 'Hello World' apps to enterprise solutions. Just run the server, define your policy, and integrate it.
{{< /callout >}}

---

## Three Core Principles of Zero Trust

1. **Never Trust, Always Verify**
   Every access request, regardless of origin or previous validation, must be verified before granting access. This principle ensures that trust is not assumed but continuously validated.

2. **Enforce Least Privilege Access**
   Users, services, and devices should only have access to the resources necessary to perform their tasks. This minimizes the risk of unauthorized actions and potential breaches.

3. **Assume Breach**
   Architect systems with the assumption that a breach can and will occur. This ensures that security measures are in place to minimize damage and maintain resilience even in compromised scenarios.

---

## How Permguard Implements ZTAuth\*

**Permguard** adopts the **ZTAuth\*** architecture to bring Zero Trust principles into the realm of authorization. To understand how this works, let’s use a comparison:

- **ZTNA (Zero Trust Network Access)**: Ensures secure, identity-based access to networks or applications by applying least privilege at the network boundary.

- **ZTAuth\* (Zero Trust Auth\*)**: Ensures secure, identity-based execution of actions on resources by enforcing least privilege at the application boundary. Built for eventual consistency, the security model is incrementally synchronized across applicative nodes in an immutable, versioned manner.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d15.png"/>
</div><br/>

Looking at the diagram, you can see the difference between **ZTAuth\*** and **Zero Trust Network Access (ZTNA)**. ZTNA protects network boundaries, while **ZTAuth\***  secures applications, giving detailed control and consistent security.

{{< callout context="tip" icon="rocket" >}}
Asynchronous by Design: Built to Mirror Reality, Not Mask It — Robust Where Synchronous Fails.
{{< /callout >}}

The ZTAuth\* architecture supports administrative services like:

- **Application Administration Point (AAP)**: Manages applications and related configurations.

- **Policy Administration Point (PAP)**: Defines and manages policies.

- **Policy Information Point (PIP):** Provides information required to make authorization decisions.

- **Policy Decision Point (PDP):** Evaluates policies and makes decisions.

- **Policy Enforcement Point (PEP):** Enforces decisions made by the PDP.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d5.png"/>
</div>

However, **ZTAuth\*** introduces a significant difference: it defines **Auth\*** models that can be transferred to `Proximity` nodes.
These models are incrementally synchronized to application nodes as git-like commit-based snapshots.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d16.png"/>
</div><br/>

To ensure proper functionality, these models must have the following characteristics:

- **Transferable and Verifiable:** Operates smoothly across systems and environments, with verifiable origins certified by the `Authorization Server`.

- **Versionable and Immutable:** Ensures integrity, auditability, and backward compatibility for secure and reliable operations.

- **Resilient to Disconnection:** Supports eventual consistency, allowing functionality in partially connected or disconnected environments.

---

## Application Boundaries

**ZTAuth\*** is designed to work with `eventual consistency`, supporting environments where connectivity is partial or network reliability is limited. Changes are packaged into versioned, immutable data structures and distributed asynchronously in incremental updates.

Every resource action at the application boundary is verified against strict, identity-based security policies aligned with an authorization schema.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d17.png"/>
</div>

The **application boundary** refers not only to APIs exposed to external consumers but also to interactions between machines or services within the application ecosystem. These interactions can involve various protocols and technologies, including synchronous requests, asynchronous messaging, and event-driven architectures. By covering all these layers, **ZTAuth\*** ensures that security policies are enforced consistently across different communication methods.

Today, the application boundary is no longer limited to traditional ingress APIs. It also includes:

- Event streaming,

- Messaging systems,

- AI agents,

- IoT sensors,

and many more technologies. These components all interact within and beyond the application boundary.

In the **ZTAuth\*** architecture, each application boundary—whether it represents a single microservice or a larger system—has a **Policy Decision Point (PDP)** deployed. Communication between application boundaries occurs when one boundary requests an action on a resource managed by another boundary. When the request is received, it is securely executed using identity-based policies and enforcing the principle of least privilege at the application boundary.

This approach makes it easier to envision how different organizations, operating across various networks, could securely federate their systems. With each application boundary enforcing its own policies while communicating securely with others, the model offers scalability and security for distributed environments.

---

## Learn More

To explore these concepts further, refer to the following articles:

- [**ZTAuth\*: A Paradigm Shift in AuthN, AuthZ, and Trusted Delegations**](https://medium.com/ztauth/ztauth-a-paradigm-shift-in-authn-authz-and-trusted-delegations-029801de8b0b)

- [**Resources, Actions and Applications in the Context of Autonomous and Disconnected Challenges**](https://medium.com/ztauth/resources-actions-andapplications-in-the-context-of-autonomous-and-disconnected-challenges-b261d37cb28a)

- [**Unlocking Zero Trust Delegation through Permissions and Policies**](https://medium.com/ztauth/unlocking-zero-trust-delegation-through-permissions-and-policies-f2952f56f79b)

- [**Introducing the ZTAuth\* Architecture**](https://medium.com/ztauth/introducing-the-ztauth-architecture-8d220ba008d1)

- [**Introducing the Identity Actor Model and Renaming Architecture Components for Better Clarity**](https://medium.com/ztauth/introducing-the-identity-actor-model-and-renaming-architecture-components-for-better-clarity-f854191f6cb9)

- [**Identity Actor Model Specification**](https://github.com/ztauthstar/ztauthstar-specs/blob/main/identity-actor-mode-spec/01/identity_actor_model_spec_01.md)

---

With PermGuard and ZTAuth\*, authorization becomes a central part of modern security, not just an extra step.
