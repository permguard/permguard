---
title: "Managing Ledgers"
slug: "Managing Ledgers"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "managing-ledgers-877e4c04952b438fb838d3ceff1aedff"
weight: 3012
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** supports multiple **ledgers** for each **remote**, allowing flexible management of both **coding** and **provisioning** tasks.

When making changes, it is important to **specify the remote** where these changes will be pushed.

## Checking out a Ledger

To ensure that changes are provisioned correctly, you must first **check out** the appropriate **ledger**.

To check out a ledger, use the **`checkout`** command:

```bash
 permguard checkout origin/273165098782/pharmaauthzflow
```

In this command, the first parameter is the **remote**, followed by the **zone ID**, and finally the **ledger identifier**. The format used is `<remote>/<zone-id>/<ledger-name>`.
