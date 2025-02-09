---
title: "Why Permguard"
slug: "Why Permguard"
description: ""
summary: ""
date: 2024-09-26T11:32:26+02:00
lastmod: 2024-09-26T11:32:26+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "why-permguard-62e42298f99ff7b907d6173b43e4d355"
weight: 1002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
In today's digital world, **identity is the foundation** of most security systems. Authentication has improved with standards like Single Sign-On, OAuth, and OpenID Connect, but **authorization is still fragmented and less developed**.

{{< callout context="tip" icon="rocket" >}}
**PermGuard** is powerful yet easy to use. Its advanced architecture ensures security and flexibility, while integration remains simple—whether for a basic app or a complex enterprise system. Just run the server, define your policy, and integrate it seamlessly.
{{< /callout >}}

## The Problem with Authorization Today

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d22.webp"/>
</div><br/>

Most systems see **authorization** as a secondary concern, often tightly linked to applications or identity providers. This leads to several challenges:

- **No Standardization**: Unlike authentication, authorization lacks universal protocols or dedicated frameworks.
- **Tied to Identity Providers**: Authentication answers *"Who are you?"*, while authorization answers *"What are you allowed to do?"*. These should be separate but equally important.
- **Difficult Integration**: Existing solutions are either too specific to an application or too generic, making it hard to fit the needs of modern systems.
- **Complex Governance**: Without a clear and independent authorization layer, managing permissions becomes inconsistent and hard to scale.

## The Need for a Dedicated Authorization Layer

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d8.webp"/>
</div><br/>

Just as authentication has evolved with dedicated identity providers and standardized protocols, **authorization also needs its own dedicated layer**. This layer should be:

- **Standardized**: A consistent way to define, enforce, and manage permissions across systems.
- **Independent from Identity**: Authorization should focus on *"what you can do"*, not just *"who you are"*, working separately from identity providers.
- **Flexible and Interoperable**: Able to integrate with different identity providers while maintaining a unified authorization model.
- **Governance-Friendly**: Transparent and easy to audit, ensuring compliance with security and regulatory requirements.

## Integration with Your Own Identity Provider

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d11.webp"/>
</div>

**PermGuard** follows the **Bring Your Own Identity (BYOI)** approach, allowing integration with existing identity providers. It supports open-source solutions like **Keycloak** as well as commercial platforms. This flexibility lets organizations keep their preferred authentication systems while using **PermGuard** for advanced authorization management.

With **APIs** or **CLI tools**, organizations can import identity data, such as users or groups, from their chosen provider into **PermGuard**. Importantly, identity provider interactions are not built into **PermGuard** itself. This keeps **PermGuard** vendor-agnostic, focusing only on authorization.

## What Permguard Brings to the Table

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d9.webp"/>
</div><br/>

**PermGuard** is built to solve authorization challenges with an open-source, flexible, and dedicated approach. Key features include:

- **Separation of Concerns**: Authorization is managed independently from authentication, ensuring clarity, scalability, and easier maintenance.
- **Integration-First Design**: Supports multiple policy languages and flexible APIs, making integration into existing systems seamless.
- **Governance-Ready**: Includes tools to define, enforce, and audit policies, simplifying compliance and governance management.

## A Future of Simplified Authorization

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d12.webp"/>
</div><br/>

**PermGuard** envisions a future where authorization is a core security component, not an afterthought. With a dedicated layer, it helps organizations:

- Build secure and scalable systems.
- Maintain consistent access control across applications and environments.
- Establish **Trusted Statements** such as **Trusted Elevation** and **Trusted Delegation**, enabling organizations to federate securely while following Zero Trust principles.
- Simplify governance and compliance.

**Authorization** should receive the same attention and innovation as authentication. With **PermGuard**, organizations get a reliable, flexible, and future-ready solution to manage permissions efficiently.
