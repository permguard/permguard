---
title: "Ledgers"
slug: "Ledgers"
description: ""
summary: ""
date: 2023-08-21T22:44:27+01:00
lastmod: 2023-08-21T22:44:27+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "ledgers-50fb7fecb28949e0af3be49b7d2954c5"
weight: 2301
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

In **Permguard**, multiple zones can be created, and each zone can have multiple **policy ledgers**.
This provides a structured way to manage `authz` components such as **schemas, policies, and permissions**.

{{< callout context="note" icon="info-circle" >}}
In the [MagicFarmacia sample](/docs/0.0.x/getting-started/hands-on-example/) a ledger is created to contain the policies.
{{< /callout >}}

## Policy Ledger

A **Policy Ledger** is a logical structure used to organize `policies`, making it easier to manage authorization rules efficiently.

```json
{
  "name": "magicfarmacia",
}
```
