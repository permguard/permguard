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

In **Permguard**, multiple ledgers can be created, and each ledger can have multiple **policies**.

{{< callout context="note" icon="info-circle" >}}
In the [MagicFarmacia sample](/docs/0.1.x/getting-started/hands-on-example/),
the policy **`view-branch-inventory`** controls access to the inventory of a pharmacy branch.
{{< /callout >}}

## Policy

A **Policy** defines what is allowed or denied within an authorization model.
It sets rules for actions on resources, ensuring secure and controlled access.
