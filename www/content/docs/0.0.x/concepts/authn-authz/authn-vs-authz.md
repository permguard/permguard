---
title: "AuthN vs AuthZ"
slug: "AuthN vs AuthZ"
description: ""
summary: ""
date: 2023-08-01T00:17:36+01:00
lastmod: 2023-08-01T00:17:36+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authn-vs-authz-790ad1dfca1124d298179d82f4715ef8"
weight: 2101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
**Authentication (`AuthN`)** and **Authorization (`AuthZ`)** are two distinct but interconnected security functions.  
They often appear together in a workflow, but they solve different problems.

- **`Authentication`** verifies the identity of a person, service, or device, ensuring that the requester is genuine. Common authentication methods include:
  - Username and Password  
  - Multi-Factor Authentication (MFA)  
  - Biometric Authentication  
  - Public Key Certificates  

  Authentication establishes **who** is initiating the request.

{{< callout context="note" icon="info-circle" >}}
Identity Management: **Permguard** follows a **Bring Your Own Identity (BYOI)** model for `AuthN`, supporting any identity source.
{{< /callout >}}

- **`Authorization`** determines **what** the authenticated entity is allowed to do.  
It governs access to resources, actions, or operations and can be role-based or policy-based.
Authorization decisions are typically dynamic and context-dependent, especially in distributed and Zero Trust architectures.

Authentication and authorization work together: authorization has no meaning without a verified identity.

{{< callout context="tip" icon="layers" >}}
**Identity Models:**  
Modern systems use different identity models:  

- **Centralized IdPs** (e.g., OAuth/OIDC providers) for human identity  
- **Self-Sovereign Identity (SSI)** for decentralized, user-controlled credentials  
- **Machine Identity** like [WIMSE](https://datatracker.ietf.org/group/wimse/documents/) for Workload Identity in Multi System Environments.

Permguard is designed to interoperate with all of them.
{{< /callout >}}
