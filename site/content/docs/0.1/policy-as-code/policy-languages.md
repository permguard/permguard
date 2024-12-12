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

`PermGuard` enforces a mandatory `single schema` for each `repository`.

To enhance the developer experience, each policy language can define its own schema grammar.
For example, when using `Cedar`, PermGuard leverages the `official schema` defined by the Cedar language.

However, for integrated languages that lack an official schema, it is necessary to create a custom schema tailored to that language to ensure compatibility and alignment with PermGuard's unified model.

{{< callout context="note" icon="info-circle" >}}
This approach guarantees a unified layer of resources and actions that remains interoperable across different applications, even when using different languages.
{{< /callout >}}

While each language can extend this schema to accommodate its specific requirements, there is always a shared foundational layer that ensures consistency.

Moreover, since everything is managed on an immutable policy ledger, this design provides robust version management, supporting multiple versions of the languages and schemas in use.
