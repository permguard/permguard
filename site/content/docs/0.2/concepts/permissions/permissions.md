---
title: "Permissions v0.2"
description: ""
summary: ""
date: 2023-08-01T00:25:01+01:00
lastmod: 2023-08-01T00:25:01+01:0
draft: false
menu:
  docs:
    parent: ""
    identifier: "permissions-751a351334c2c7f0677b495e06715f7f"
weight: 2304
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

In `Permguard`, multiple repositories can be created, and each of them can have multiple **permissions**.

{{< callout context="note" icon="info-circle" >}}
In the context of the [MagicFarmacia sample](/docs/overview/adoption-through-example#integration-use-case-pharmacy-branch-management), the permission `branch-pharmacist` permission would be used to grant the ability to view the inventory and manage orders for a pharmacy branch.
{{< /callout >}}

## Permission

A permission serves as a logical representation of a list of policies that can either be permitted or forbidden in an authorization model. Permissions are created to be ultimately associated with identities.

{{< callout context="caution" icon="alert-triangle" >}}
Permissions can be defined using either PermScript or YAML.
{{< /callout >}}

```json
{
  "name": "branch-pharmacist",
  "permit": ["view-branch-inventory", "manage-branch-orders"],
  "forbid": null
}
```
