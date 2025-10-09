---
title: "Overview"
slug: "Overview"
description: ""
summary: ""
date: 2023-08-20T17:14:43+01:00
lastmod: 2023-08-20T17:14:43+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "permguard-paradigm-24b9ae1383440efb49528d1ecc48ab03"
weight: 1001
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
**Permguard** is a modern, open-source authorization server designed to follow **Zero Trust** principles.

It implements the [Zero Trust Auth\* (ZTAuth\*)](https://spec.ztauthstar.com) protocol to ensure that every access request is continuously verified, regardless of application boundaries or execution context.

The main idea is to ensure that trust is never assumed but always validated at the application boundary. Integrating **Permguard** to handle incoming requests ensures that every request is verified before access is granted.

This applies not only to APIs but also to any type of incoming request, including async messages, WebSocket connections, and more.

Each incoming request generates an authorization request that is evaluated by the **Permguard AuthZ Server**. The server responds with a decision to either allow or deny the request.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d1.webp"/>
</div>
</br>

Designed for `cloud-native`, `edge`, and `multi-tenant` environments, **Permguard** can be used in any context, including IoT, AI agents, and more. It allows you to update authorization policies without modifying your application code, saving time and effort.

These policies are centrally managed, allowing organizations to enforce consistent security rules across multiple applications without changing each service individually. This ensures compliance with corporate governance by providing a single point of control for defining, updating, and auditing authorization policies in real time.

{{< callout context="tip" icon="rocket" >}}
**Permguard** is powerful yet easy to use. Its advanced architecture ensures security and flexibility, while integration remains simple—whether for a basic app or a complex enterprise system. Just run the server, define your policy, and integrate it seamlessly.
{{< /callout >}}

**Permguard** can be deployed anywhere: `public or private clouds`, `managed infrastructure`, `Kubernetes`, `serverless` systems, or even in `partially connected` environments where stable connectivity is limited. It is also a great fit for `edge nodes` and `IoT` ecosystems, providing secure and consistent permission management across different environments.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d13.webp"/>
</div>

It follows a `Bring Your Own Identity (BYOI)` approach, meaning it integrates with your existing authentication system instead of replacing it.

{{< callout context="note" icon="info-circle" >}}
The main goal of **Permguard** is to provide a strong authorization system with built-in administrative tools.
{{< /callout >}}

The solution is `language-agnostic`, supporting multiple policy languages, starting with [Cedar Policy Language](https://www.cedarpolicy.com/en).
Developers can choose their preferred language from the supported options while ensuring that all federated **Permguard** servers work smoothly together, even if they use different languages internally.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d18.webp"/>
</div>

Each language is integrated with a lightweight abstraction layer, providing flexibility while reserving only a few keywords.

To enforce access control, the application can use an **SDK** or directly integrate with the native **APIs**.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d19.webp"/>
</div>

{{< callout context="note" icon="info-circle" >}}
There are SDKs available for multiple programming languages, including **Go**, **Java**, **Node.js**, and **Python**. More SDKs are being developed to support additional languages.
{{< /callout >}}

This approach allows precise control over who or what can access resources while keeping the system flexible and easy to use.

- `Who`: *Identities (Users and Actors)*
- `Can Access`: *Permissions granted by attaching policies*
- `Resources`: *Resources targeted by permissions*

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/d14.webp"/>
</div>
