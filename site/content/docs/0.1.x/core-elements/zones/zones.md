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
**Permguard** supports `multi-zone` architecture, allowing the creation of multiple **zones**.
Each zone is fully isolated, with its own tenants, identities, ledgers, schemas, policies, and permissions.

{{< callout context="caution" icon="alert-triangle" >}}
It is recommended to use a separate zone for each environment, such as development, staging, and production.
This best practice helps reduce security risks.
{{< /callout >}}

It is important to note that **Permguard** does not include an authentication layer.
The adopter is responsible for implementing or integrating authentication at the zone level.

{{< callout context="note" icon="info-circle" >}}
In the [MagicFarmacia sample](/docs/0.1.x/getting-started/hands-on-example/) the `demo-zone` zone is created.
{{< /callout >}}

Each zone is uniquely identified by a `name`.

```json
{
  "zone_id": 273165098782,
  "name": "magicfarmacia-dev"
}
```
