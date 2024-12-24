---
title: "Policy Ledgers"
slug: "Policy Ledgers"
description: ""
summary: ""
date: 2023-08-21T22:44:27+01:00
lastmod: 2023-08-21T22:44:27+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "policy-ledgers-50fb7fecb28949e0af3be49b7d2954c5"
weight: 2301
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

In **Permguard**, multiple applications can be created, and each of them can have multiple **policy ledgers**. This provides a structured method for managing the `authz` components such as schemas, policies and permissions.

{{< callout context="note" icon="info-circle" >}}
In the context of the [MagicFarmacia sample](/docs/0.1/getting-started/adoption-through-example#integration-use-case-pharmacy-branch-management), the system operates within a microservice architecture.
{{< /callout >}}

## Policy Ledger

A Policy Ledger serves as logical representations, facilitating `policy` organization.

```json
{
  "name": "magicfarmacia",
}
```
