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

`Permguard` implements the concept of `multi-tenants`, allowing the creation of multiple **tenants** for each account.

Tenants play a crucial role in managing the authorizations and they can be used to `partition` `resources` and `actions` effectively.
This is quite useful in scenarios where the adopter intends to use Permguard for developing a multi-tenant application, such as Software as a Service (SaaS).

{{< callout context="note" icon="info-circle" >}}
In the context of the [MagicFarmacia sample](/docs/overview/adoption-through-example#integration-use-case-pharmacy-branch-management), there would be multiple tenants, one for each branch of the pharmacy, such as `matera-branch`, `pisa-branch`, and so on.

This allows for effective partitioning of resources and actions for each branch in a tenant-specific manner.

`Multi-tenant management` is particularly valuable in the context of companies building `SaaS products for B2B` scenarios. In such cases, each tenant (i.e., each client of the SaaS provider) represents an organization that, in turn, offers the SaaS product as a platform to their own end users. This means that each tenant essentially becomes a separate platform, allowing the client to manage their own users, resources, and permissions independently, all within the same shared SaaS environment. This approach ensures scalability and customization, enabling each tenant to tailor the platform to the specific needs of their end users.
{{< /callout >}}

Each tenant is identified by a unique `name`.

```json
{
  "name": "matera-branch"
}
```
