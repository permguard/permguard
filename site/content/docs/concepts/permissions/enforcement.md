---
title: "Enforcement"
slug: "Enforcement"
description: ""
summary: ""
date: 2023-08-01T00:25:01+01:00
lastmod: 2023-08-01T00:25:01+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "enforcement-f9bdc944c7cb7b27eea146c4f8ef46c3"
weight: 2305
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
In `PermGuard`, enforcement is ensured by the Policy Enforcement Point (PEP). Its intent is to verify if an identity can execute certain actions on certain resources and domains.

## Enforcement

To complete the enforcement process, the PEP queries the Policy Decision Point (PDP).

```json
{
  "identity": {
    "uur": "uur:581616507495:permguard:identities:iam:user/mario.rossi"
  },
  "domain": "renting",
  "resources": [ "car" ],
  "actions": [ "car:list" ],
}
```
