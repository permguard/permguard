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
`Permguard` is an open-source `Zero-Trust Auth* Provider` designed for cloud-native, edge, and multi-tenant applications. It operates independently of application code and utilizes Policy-as-Code to provide centralized and scalable permission management.

{{< callout context="note" icon="info-circle" >}}
Decoupling the authorization layer from the application code allows policies to be managed without changing the application code.

This approach also simplifies creating a central authorization layer to manage permissions across multiple applications, much like modern solutions centralize identity access management.
{{< /callout >}}

The platform is designed to be language-agnostic and currently uses a YAML-based language called `PermYAML`. It is built to be extensible, with plans to add support for additional languages in the future.

Through the chosen approach, it is possible to specify who or what can access resources through finely detailed permissions.

- `Who`: *Identities (Users and Roles)*
- `Can Access`: *Permissions granted by attaching policies*
- `Resources`: *Resources targeted by permissions*

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d1.png"/>
</div>

{{< callout context="note" icon="info-circle" >}}
Identity Management: Permguard adopts the **Bring Your Own Identity (BYOI)** model, syncing seamlessly with external identity sources for streamlined and secure management.
{{< /callout >}}

`Permguard` enables the creation of `accounts` to manage `isolated models`.
Additionally, it supports `tenancy`, allowing each `account` to have multiple isolated tenants. Each tenant can further manage its own isolated `resources`, ensuring flexible and secure multi-tenant management.

{{< callout context="note" icon="info-circle" >}}
To enforce the access control process, the application can integrate one of the available **SDKs** or manually integrate the native **APIs**.
{{< /callout >}}
