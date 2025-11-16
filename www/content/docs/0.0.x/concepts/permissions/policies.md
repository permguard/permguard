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
weight: 2304
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

In **Permguard**, multiple ledgers can be created, and each ledger can have multiple **policies**.

{{< callout context="note" icon="info-circle" >}}
In the [PharmaAuthZFlow sample](/docs/0.0.x/getting-started/hands-on-example/) policies such as **`platform-manager`** are created.
{{< /callout >}}

## Policy

A `policy` defines how permissions and denials are expressed within a trust model, describing which actions are allowed or rejected under specific conditions.

{{< callout context="note" icon="info-circle" >}}
**Policies** are not tied to a single `policy language`: different languages or representations can be used as long as they produce consistent and verifiable authorization outcomes.
{{< /callout >}}
