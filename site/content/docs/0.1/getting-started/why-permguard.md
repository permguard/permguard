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
In today’s digital ecosystem, **identity has become the foundation** of most security architectures. While significant progress has been made in standardizing authentication (e.g., Single Sign-On, OAuth, OpenID Connect), **authorization remains fragmented and underdeveloped**.

{{< callout context="tip" icon="rocket" >}}
Permguard may seem complex, but it’s not: its internal architecture is sophisticated, yet integration is simple—perfect for everything from 'Hello World' apps to enterprise solutions. Just run the server, define your policy, and integrate it.
{{< /callout >}}

### The Problem with Authorization Today

Most systems treat **authorization** as a secondary concern, tightly coupled to applications or identity providers. This creates several challenges:

- **No Standardization**: Authorization lacks universal protocols or dedicated frameworks, unlike authentication, which is more mature.
- **Coupling with Identity**: Authorization is often tied to identity providers. While authentication answers *"Who are you?"*, authorization answers *"What are you allowed to do?"*. These are separate but equally important.
- **Governance Complexity**: Without a clear and dedicated layer, managing permissions becomes inconsistent and difficult to scale.
- **Integration Challenges**: Existing solutions are either too specific to an application or too generic, making it hard to meet the diverse needs of modern systems.

### The Need for a Dedicated Authorization Layer

Just like authentication has matured with dedicated identity providers and standardized protocols, **authorization also needs its own dedicated layer**. This layer should be:

- **Standardized**: A consistent way to define, enforce, and manage permissions across systems.
- **Decoupled from Identity**: Authorization should work independently of identity providers, focusing on "what you can do" rather than "who you are."
- **Governance-Friendly**: Built with transparency, making it easy to audit and align with compliance requirements.
- **Flexible and Interoperable**: Capable of integrating with various identity providers while maintaining a consistent authorization model.

### Integration with Your Own Identity Provider

Permguard follows the **Bring Your Own Identity (BYOI)** approach, allowing you to integrate with existing identity providers. Examples include open-source solutions like **Keycloak**, as well as commercial identity platforms. This flexibility ensures that organizations can continue using their preferred authentication systems while leveraging Permguard for robust authorization management.

Using **APIs** or **CLI tools**, organizations can import identity data from their chosen provider into Permguard, such as user roles or groups. Importantly, interactions with identity providers are not built into Permguard itself. This design choice ensures that Permguard remains vendor-agnostic, focusing exclusively on authorization.

### What Permguard Brings to the Table

**Permguard** is designed to address the challenges of authorization by providing an open-source, flexible, and dedicated solution. Key features include:

- **Separation of Concerns**: Authorization is treated as its own domain, separate from authentication. This ensures clarity, scalability, and maintainability.

- **Governance-Ready**: Permguard includes tools to define, enforce, and audit policies, making it easier to meet compliance and governance requirements.

- **Integration-First Design**: Permguard supports multiple policy languages and flexible APIs, making it easy to integrate into existing systems.

### A Future of Simplified Authorization

Permguard envisions a future where authorization is no longer an afterthought. By establishing a dedicated layer, it empowers organizations to:

- Build systems that are secure and scalable.

- Simplify governance and compliance.

- Ensure consistent access control across different applications and environments.

**Authorization** deserves the same focus and innovation that authentication has received. With Permguard, organizations have a reliable, flexible, and future-ready solution to manage permissions effectively.
