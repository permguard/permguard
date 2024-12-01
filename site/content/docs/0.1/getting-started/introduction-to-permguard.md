---
title: "Introduction to Permguard"
slug: "Introduction to Permguard"
description: ""
summary: ""
date: 2023-08-20T17:14:43+01:00
lastmod: 2023-08-20T17:14:43+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "introduction-to-permguard-24b9ae1383440efb49528d1ecc48ab03"
weight: 1001
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
`PermGuard` is a modern, open-source authorization provider built on `Zero Trust` principles and the Zero Trust Auth* ([ZTAuth*](https://medium.com/ztauth)) framework.

It helps you easily manage permissions by defining who can do what in your system.

Designed for `cloud-native`, `edge`, and multi-tenant environments, PermGuard allows you to update your authorization policies without changing your application code, saving time and effort.

These policies are centrally managed, ensuring compliance with corporate governance.

`PermGuard` can be deployed anywhere: `public or private clouds`, `managed infrastructure`, `Kubernetes`, `serverless` systems, or even in `partially connected` environments where consistent connectivity is a challenge. It is also ideal for use in `edge nodes` and `IoT` ecosystems, ensuring secure and consistent permission management across diverse setups.

It follows a `Bring Your Own Identity (BYOI)` approach, meaning it works with your existing authentication system instead of replacing it.
You can configure identity sources to migrate identities from your current `identity provider`, ensuring all permissions are managed consistently and centrally, no matter where you use `PermGuard`.

{{< callout context="note" icon="info-circle" >}}
The main goal of PermGuard is to provide a robust authorization provider along with its own administrative and authorization components. It allows the association of identity sources through ingestion APIs, but these identity sources must be integrated using bespoke solutions. This approach ensures that PermGuard remains flexible and avoids unnecessary customizations and complexity in management.
{{< /callout >}}

The solution is `language-agnostic`, supporting multiple policy languages, starting with [Cedar Policy Language](https://www.cedarpolicy.com/en).
Developers can use their preferred language from the ones integrated, while ensuring all federated PermGuard servers work seamlessly together, even if they use different languages internally.

`PermGuard `uses a common `schema` to define `Resources`, `Actions`, and `Identities`, ensuring consistency.
Each language is integrated with a small abstraction layer that doesn’t limit developers, except for a few reserved keywords.

{{< callout context="note" icon="info-circle" >}}
To enforce the access control process, the application can integrate one of the available **SDKs** or manually integrate the native **APIs**.
{{< /callout >}}

This approach allows detailed permissions to specify who or what can access resources, while keeping the system flexible and easy to use.

- `Who`: *Identities (Users and Roles)*
- `Can Access`: *Permissions granted by attaching policies*
- `Resources`: *Resources targeted by permissions*

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d1.png"/>
</div>
