---
title: "Resource"
slug: "Resource"
description: ""
summary: ""
date: 2024-12-26T22:53:00+01:00
lastmod: 2024-12-26T22:53:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "resource-b57c30089bc94b658fe1efd9ba399980"
weight: 5204
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `Resource` specifies the entity requesting access to a resource.

- `type`: A required string value that specifies the type of the Resource.
- `id`: A required string value containing the unique identifier of the Resource, scoped to the type.
- `properties`: An optional JSON object containing any number of key-value pairs, which can be used to express additional properties of a Resource.

```json
{
  "type": "MagicFarmacia::Platform::Account::Subscription",
  "id": "e3a786fd07e24bfa95ba4341d3695ae8",
  "properties": {
    "active": true
  }
}
````

## Accepted Values

The `type` and `id` fileds accept any valid string which is validated by the underlying policy engine based on its validation rules.
