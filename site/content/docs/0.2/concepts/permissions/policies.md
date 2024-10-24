---
title: "Policies v0.2"
slug: "Policies"
description: ""
summary: ""
date: 2023-08-21T22:44:27+01:00
lastmod: 2023-08-21T22:44:27+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "policies-d204a260e63c26a932030734402bbffa"
weight: 2303
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

In `Permguard`, multiple repositories can be created, and each of them can have multiple **policies**.

{{< callout context="note" icon="info-circle" >}}
In the context of the [MagicFarmacia sample](/docs/overview/adoption-through-example#integration-use-case-pharmacy-branch-management), the policy `view-branch-inventory` would be used to control view access to the inventory of a pharmacy branch.
{{< /callout >}}

## Policy

A policy serves as a logical representation of what can be permitted or forbidden in an authorization model.

{{< callout context="caution" icon="alert-triangle" >}}
Policies can be defined using either PermScript or YAML.
{{< /callout >}}

```json
{
  "name": "view-branch-inventory",
  "actions": ["inventory:view"],
  "resources": ["uur::::pharmacy-branch:inventory/*"]
}
```
