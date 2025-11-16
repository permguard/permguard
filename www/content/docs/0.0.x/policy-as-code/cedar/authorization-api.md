---
title: "AuthZApi"
slug: "AuthZApi"
description: ""
summary: ""
date: 2025-02-14T00:34:10+01:00
lastmod: 2025-02-14T00:34:10+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authorization-api-f4b0330df22d49649f63eb411f00e47b"
weight: 4101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

This section specifies the **Cedar** `AuthZApi Model` override.

> If no specific override is provided, the generic `AuthZApi Model` specification applies.

{{< callout context="caution" icon="alert-triangle" >}}
Properties must conform to the JSON structure defined for the <a href="https://docs.cedarpolicy.com/auth/entities-syntax.html#attrs" target="_blank" rel="noopener noreferrer">entities attributes object</a>,
whereas the Context must adhere to the JSON structure specified for the <a href="https://docs.cedarpolicy.com/auth/entities-syntax.html#context" target="_blank" rel="noopener noreferrer">context object</a>.
{{< /callout >}}

## Entities

The `Entities` object is a `set of attributes` that represent policy's entities.

```json
{
  "authorization_model": {
    "entities": {
      "schema": "cedar",
      "items": [
        {
          "uid": {
            "type": "MagicFarmacia::Platform::Subscription",
            "id": "e3a786fd07e24bfa95ba4341d3695ae8"
          },
          "attrs": {
            "active": true
          },
          "parents": []
        }
      ]
    }
  }
}
```

---
**authorization_model/entities/schema**: *the schema type (default `CEDAR`, options `CEDAR`).*

---
**authorization_model/entities/items**: *items has to match the `CEDAR` entities structure.*

---

## Subject

The `Subject` is mapped to the internal `Permguard`  subject structure for the `Cedar` policy.

| TYPE       | CEDAR TYPE                      |
|------------|---------------------------------|
| USER       | Permguard::IAM::User            |
| WORKLOAD   | Permguard::IAM::Workload        |

The `CEDAR TYPE` must be used in the `Cedar` policy.

```cedar
@id("platform-auditor")
permit(
  principal == Permguard::IAM::User::"platform-auditor"
);
```

## Resource

The `Resource` has to satisfy the `Cedar` resource structure.

```cedar
@id("platform-auditor")
permit(
  resource is MagicFarmacia::Platform::Subscription
);
```

## Action

The `Action` has to satisfy the `Cedar` action structure.

```cedar
@id("platform-auditor")
permit(
  action == MagicFarmacia::Platform::Action::"view",
);
```
