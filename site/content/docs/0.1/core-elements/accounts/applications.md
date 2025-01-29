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

**Permguard** implements the concept of `multi-zone`, allowing the creation of multiple **zones**.
These zones are isolated from one another, enabling each zone to have its distinct set of tenants, identities, ledgers, schemas, policies and permissions.

{{< callout context="caution" icon="alert-triangle" >}}
It is recommended to utilize a distinct zone for each environment, such as development, staging, and production, this as a best practice to mitigate potential security risks.
{{< /callout >}}

It is important to note that the **Permguard** does not include an authentication layer. It is the responsibility of the adopter to either implement or integrate the authentication layer at the zone level.

{{< callout context="note" icon="info-circle" >}}
In the context of the [MagicFarmacia sample](/docs/0.1/getting-started/adoption-through-example#integration-use-case-pharmacy-branch-management), the `magicfarmacia-dev` zone represents the development environment, while the `magicfarmacia-prod` zone represents the production environment.

This approach follows best practices to ensure the isolation of resources and permissions between environments. Beyond the per-environment zone setup, a company might also decide to further segment by having separate zones for each zone or a shared zone for multiple zones.
{{< /callout >}}

Each zone is identified by a unique `name`.

```json
{
  "zone_id": 268786704340,
  "name": "magicfarmacia-dev"
}
```
