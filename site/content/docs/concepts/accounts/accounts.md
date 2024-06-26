---
title: "Accounts"
slug: "Accounts"
description: ""
summary: ""
date: 2023-08-21T22:43:47+01:00
lastmod: 2023-08-21T22:43:47+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "accounts-69d32716e94a108f78c3112eaec3e98e"
weight: 2201
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
`PermGuard` implements the concept of `multi-account`, allowing the creation of multiple **accounts**.
These accounts are isolated from one another, enabling each account to have its distinct set of tenants, identities, repositories, schemas, policies and permissions.

{{< callout context="caution" icon="alert-triangle" >}}
It is recommended to utilize a distinct account for each environment, such as development, staging, and production, this as a best practice to mitigate potential security risks.
{{< /callout >}}

It is important to note that the `PermGuard` does not include an authentication layer. It is the responsibility of the adopter to either implement or integrate the authentication layer at the application level.

Each account is identified by a unique `numeric identifier` and it is associated to an unique `name`.

```json
{
  "account_id": 581616507495,
  "name": "dev-car-rental"
}
```
