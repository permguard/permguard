---
title: "Identities"
slug: "Identities"
description: ""
summary: ""
date: 2023-08-21T22:43:55+01:00
lastmod: 2023-08-21T22:43:55+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "identities-c92112e56e385ee44401f0bfb5d67e76"
weight: 2202
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

An `identity` is an unique entity that represents either an **user** or a **role**.

Identities are linked to identity sources. By default, there is the native `default` identity source, and more can be created.

```json
{
  "identity_source_id": "1fcb1d54-2ea4-4f62-909b-bd5a6c4a2ab3",
  "account_id": 567269058122,
  "name": "default"
}
```

## Principal

A `Principal` is an human user or workload with granted permissions that authenticates and make requests, specifically:

- A user
- A role
- An assumed role (role assumed by a user or a role assumed by a workload).

## User

An `User` is an identity representing a single person or FID (Function Identifier) that has specific permissions.

```json
{
  "identity_id": "4ab1f4a4-0198-4cee-9f50-a661f4f739d7",
  "account_id": 567269058122,
  "identity_source_id": "7c863e36-2575-4989-b103-fce308bdf55b",
  "identity_type": "user",
  "name": "nicola.gallo",
}
```

## Role

A `Role` is an identity within an account with associated permissions.
A role can be temporaraly assumed by a `Principal` identity.

```json
{
  "identity_id": "d670a5ff-3533-4192-a033-c6ecabcd79e4",
  "account_id": 567269058122,
  "identity_source_id": "7c863e36-2575-4989-b103-fce308bdf55b",
  "identity_type": "role",
  "name": "rentalagent"
}
```
