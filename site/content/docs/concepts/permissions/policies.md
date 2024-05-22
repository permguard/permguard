---
title: "Policies"
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
In `PermGuard`, multiple repositories can be created, and each of them can have multiple **policies**.

## Policy

A policy serves as a logical representation of what can be permitted or forbidden in an authorization model.

{{< callout context="caution" icon="alert-triangle" >}}
It's important to note that a policy is represented using a JSON object; however, its definition can be expressed using the PermGuard Policy Configuration Language.
{{< /callout >}}

```json
{
    "policy_id": "4e72117e-fb2d-46d6-875a-938b2b7108c8",
    "name": "backoffice-create-car",
    "actions": [
        "car:create"
    ],
    "resources": [
        "uur:581616507495:default:car-rental:backoffice:car/*"
    ]
}
```
