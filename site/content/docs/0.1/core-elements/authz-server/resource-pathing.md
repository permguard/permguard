---
title: "Resource Pathing"
slug: "Resource Pathing"
description: ""
summary: ""
date: 2023-08-01T00:25:01+01:00
lastmod: 2023-08-01T00:25:01+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "resource-pathing-aac9fddccc2c417cbc1393e16518d34b"
weight: 2305
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

In **PermGuard**, an **Authorization Server** is a logical server that includes a set of nodes. Specifically, it consists of the following components:

- **Application Administration Point (AAP)**
- **Policy Administration Point (PAP)**
- **Policy Decision Point (PDP)**

This **Authorization Service** is responsible for managing multiple elements such as users, actors, tenants, ledgers, and more. Given the complexity of these resources, it is crucial to establish a clear and structured pathing mechanism for each resource to ensure efficient management and access control.

{{< callout context="note" icon="info-circle" >}}
An environment can include multiple **Authorization Servers**, making it essential to reference each one explicitly. This is because there is no guarantee that the same resource will be unique across all servers.
{{< /callout >}}

```text
   protocol             host              account
  ┌───┴────┐┌───────────┴───────────┐ ┌────┴─────┐
  permguard@nitro.aws-eu.permguard.io/676095239339
```
