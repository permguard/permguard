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

**Permguard** is designed with Zero Trust principles at its core, leveraging the **ZTAuth*** architecture to ensure secure, scalable, and reliable authorization in modern, distributed environments.

---

## Three Core Principles of Zero Trust

1. **Never Trust, Always Verify**
   Every access request, regardless of origin or previous validation, must be verified before granting access. This principle ensures that trust is not assumed but continuously validated.

2. **Enforce Least Privilege Access**
   Users, services, and devices should only have access to the resources necessary to perform their tasks. This minimizes the risk of unauthorized actions and potential breaches.

3. **Assume Breach**
   Architect systems with the assumption that a breach can and will occur. This ensures that security measures are in place to minimize damage and maintain resilience even in compromised scenarios.

---

## How Permguard Implements ZTAuth*

**Permguard** adopts the **ZTAuth*** architecture to bring Zero Trust principles into the realm of authorization. Here's how:

- **Decoupled Authorization**
  Permguard separates authorization from authentication, ensuring that access control is managed independently of identity verification. This enables consistent authorization policies across different systems and identity providers.

- **Policy-Driven Access**
  Authorization decisions in Permguard are based on clearly defined policies that align with Zero Trust principles. These policies are versioned, auditable, and enforce least privilege access.

- **Proximity Nodes for Autonomy**
  Permguard supports **proximity nodes**, allowing policies and permissions to be enforced even in partially connected or disconnected environments. This ensures continuity and security, regardless of network availability.

- **Bring Your Own Identity (BYOI)**
  Permguard integrates seamlessly with existing identity providers, such as Keycloak or commercial solutions. This flexibility ensures that organizations can adopt Zero Trust authorization without disrupting their current authentication workflows.

---

## Why ZTAuth* Matters for Authorization

The **ZTAuth*** architecture brings key benefits to modern authorization systems:

- **Scalability**: Policies and permissions are designed to scale across multi-account and multi-tenant environments.

- **Governance-Ready**: All policies are versionable and auditable, making it easier to align with compliance requirements.

- **Flexibility**: Supports integration with diverse systems and identity providers, enabling seamless adoption.

By adopting ZTAuth*, Permguard empowers organizations to implement **Zero Trust authorization** that is robust, scalable, and future-proof.

---

## Learn More

To explore these concepts further, refer to the following articles:

- [**Introducing the ZTAuth\* Architecture**](https://medium.com/ztauth/introducing-the-ztauth-architecture-8d220ba008d1)

- [**Resources, Actions and Accounts in the Context of Autonomous and Disconnected Challenges**](https://medium.com/ztauth/resources-actions-andaccounts-in-the-context-of-autonomous-and-disconnected-challenges-b261d37cb28a)

- [**Unlocking Zero Trust Delegation through Permissions and Policies**](https://medium.com/ztauth/unlocking-zero-trust-delegation-through-permissions-and-policies-f2952f56f79b)

- [**ZTAuth\*: A Paradigm Shift in AuthN, AuthZ, and Trusted Delegations**](https://medium.com/ztauth/ztauth-a-paradigm-shift-in-authn-authz-and-trusted-delegations-029801de8b0b)

---

With Permguard and ZTAuth*, authorization is no longer an afterthought—it is a core component of modern security.
