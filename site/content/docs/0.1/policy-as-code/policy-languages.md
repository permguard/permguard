---
title: "Policy Languages"
slug: "Policy Languages"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "policy-languages-eff035101e394ce3a1f33767ce0b2613"
weight: 4001
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
**PermGuard** fully supports `Cedar` as the primary policy language.

`PermGuard` enforces a **mandatory single schema** for each `ledger`.

## Schema Management in Policy Languages

To improve the developer experience, each policy language can define its own **schema grammar**.

- When using `Cedar`, **PermGuard** leverages the **official schema** defined by the Cedar language.
- For integrated languages without an official schema, a **custom schema** must be created to ensure compatibility with **PermGuard's unified model**.

{{< callout context="note" icon="info-circle" >}}
This approach ensures a **consistent layer of resources and actions**, allowing interoperability across different applications—even when using different policy languages.
{{< /callout >}}

Each language can **extend** the schema to meet its specific needs, but a **shared foundational layer** maintains consistency.

## Version Management

Since everything is managed on an **immutable policy ledger**, this design provides:

- **Version control** for policies.
- Support for **multiple schema versions** across different policy languages.
- Reliable and structured updates without breaking existing policies.
