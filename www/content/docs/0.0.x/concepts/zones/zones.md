---
title: "Zones"
slug: "Zones"
description: ""
summary: ""
date: 2023-08-21T22:43:47+01:00
lastmod: 2023-08-21T22:43:47+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "zones-69d32716e94a108f78c3112eaec3e98e"
weight: 2201
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
**Permguard** supports a `multi-zone` architecture, enabling the creation of multiple **zones**.

Each `zone` segments a distinct `trust model` and maintains its own ledgers, manifests, schemas, policies, and permissions.

{{< callout context="note" icon="info-circle" >}}
In the [PharmaAuthZFlow sample](/docs/0.0.x/getting-started/hands-on-example/), the `platform-admin-zone` is created as one of the example segments.
{{< /callout >}}

Each zone is uniquely identified by a `name`.

```json
{
  "zone_id": 273165098782,
  "name": "pharmaauthzflow-dev"
}
```
