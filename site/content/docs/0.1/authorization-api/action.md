---
title: "Action"
slug: "Action"
description: ""
summary: ""
date: 2024-12-26T22:53:00+01:00
lastmod: 2024-12-26T22:53:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "action-adfa4b0b04454902bd2046631327dd6b"
weight: 5206
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `Action` specifies the entity requesting access to a action.

- `name`: A required string value that specifies the name of the Action.
- `properties`: An optional JSON object containing any number of key-value pairs, which can be used to express additional properties of a Action.

```json
{
  "type": "cancel",
  "properties": {
    "reason": "expired subscription"
  }
}
````

## Accepted Values

The `name` any valid string which is validated by the underlying policy engine based on its validation rules.
