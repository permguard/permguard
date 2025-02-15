---
title: "AuthZ Model"
slug: "AuthZ Model"
description: ""
summary: ""
date: 2025-02-14T00:34:10+01:00
lastmod: 2025-02-14T00:34:10+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authz-model-f4b0330df22d49649f63eb411f00e47b"
weight: 4103
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

This section specifies the `Cedar` **Authz Model** override. If no specific override is provided, the generic Authz Model specification applies.

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
