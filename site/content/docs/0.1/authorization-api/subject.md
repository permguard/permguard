---
title: "Subject"
slug: "Subject"
description: ""
summary: ""
date: 2024-12-26T22:53:00+01:00
lastmod: 2024-12-26T22:53:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "subject-1f0bad1206c5497f9bcbd3f8630fe952"
weight: 5205
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The Subject specifies the entity requesting access to a resource.

- `type`: A required string value that specifies the type of the Subject.
- `id`: A required string value containing the unique identifier of the Subject, scoped to the type.
- `source`: An optional string value that specifies the source of the Subject.
- `properties`: An optional JSON object containing any number of key-value pairs, which can be used to express additional properties of a Subject.

```json
{
  "type": "user",
  "id": "alice",
  "source": "keycloak",
  "properties": {
    "department": "sales"
  }
}
````

## Accepted Values

Below are the accepted values for the `type` field:

| Accepted Values | Description     |
|-----------------|-----------------|
| user            | An user entity. |

The `id` field accepts any valid string which is validated by the underlying policy engine based on its validation rules.

Finally the `source` field accepts any valid Permguard identity source.
