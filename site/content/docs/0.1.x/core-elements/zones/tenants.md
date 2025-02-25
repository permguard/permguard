---
title: "Tenants"
slug: "Tenants"
description: ""
summary: ""
date: 2023-08-21T22:44:03+01:00
lastmod: 2023-08-21T22:44:03+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "tenants-236069559096c3069443e796d0d2bf86"
weight: 2203
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** supports `multi-tenancy`, allowing multiple **tenants** to be created within each zone.

Tenants play a key role in managing authorizations and help **partition** `resources` and `actions` efficiently.
This is especially useful for **multi-tenant** zones, such as Software as a Service (**SaaS**) platforms.

{{< callout context="note" icon="info-circle" >}}
In the [MagicFarmacia sample](/docs/0.1.x/getting-started/hands-on-example/), each pharmacy branch is a separate tenant, such as `matera-branch` or `pisa-branch`.

This setup allows each branch to manage its own resources and actions independently.

**Multi-tenant management** is particularly valuable for companies building **SaaS products for B2B**.
In these cases:

- Each tenant represents a client organization using the SaaS platform.
- The client organization can manage its own users, resources, and permissions separately.
- The shared SaaS environment remains scalable and customizable for each tenant.

This approach ensures **scalability and flexibility**, allowing each tenant to tailor the platform to its specific needs.
{{< /callout >}}

Each tenant is identified by a unique `name`.

```json
{
  "name": "matera-branch"
}
```
