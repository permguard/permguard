---
title: "Repositories"
slug: "Repositories"
description: ""
summary: ""
date: 2023-08-21T22:44:27+01:00
lastmod: 2023-08-21T22:44:27+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "repositories-50fb7fecb28949e0af3be49b7d2954c5"
weight: 2301
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
In `PermGuard`, multiple accounts can be created, and each of them can have multiple **repositories**. This provides a structured method for managing the `authz` components such as schemas, policies and permissions.

## Repository
A Repository serves as logical representations, facilitating `authz` organization.

```json
{
  "repository_id": "b7bd0df8-3183-4dfb-9a29-c2d935be0d3d",
  "account_id": 567269058122,
  "name": "car-rental"
}
```
