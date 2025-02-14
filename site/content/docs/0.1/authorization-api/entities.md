---
title: "Entities"
slug: "Entities"
description: ""
summary: ""
date: 2024-12-26T22:53:00+01:00
lastmod: 2024-12-26T22:53:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "entities-189cf01e5ee542868ec7a19096423bdf"
weight: 5203
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `Entities` object is a `set of attributes` that represent policy's entities.

```json
{
  "authorization_context": {
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
