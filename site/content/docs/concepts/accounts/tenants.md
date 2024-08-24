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

`PermGuard` implements the concept of `multi-tenants`, allowing the creation of multiple **tenants** for each account.

Tenants play a crucial role in managing the authorizations and they can be used to `partition` `resources` and `actions` effectively.
This is quite useful in scenarios where the adopter intends to use PermGuard for developing a multi-tenant application, such as Software as a Service (SaaS).

{{< callout context="note" icon="info-circle">}}
A tenant is uniquely identified by both a Tenant-ID and a Name, ensuring that there are no white spaces within the name. Policies refer to tenants using their names rather than the tenant ID to enhance readability.
{{< /callout >}}

```json
{
  "tenant_id": "0a275069-ffd0-4af6-8da0-9b64dc05c44b",
  "account_id": 567269058122,
  "name": "default"
}
```
