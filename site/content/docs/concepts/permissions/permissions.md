---
title: "Permissions"
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
In `PermGuard`, multiple repositories can be created, and each of them can have multiple **permissions**.

## Permission

A permission serves as a logical representation of a list of policies that can either be permitted or forbidden in an authorization model. Permissions are created to be ultimately associated with identities.

{{< callout context="caution" icon="alert-triangle" >}}
Permissions can be defined using either PermScript or YAML.
{{< /callout >}}

```json
{
    "name": "inventory-read",
    "permit": [
        "access-inventory"
    ],
    "forbid": []
}
```
