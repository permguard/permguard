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

Identities are linked to identity sources.

```json
{
  "identity_source_id": "1da1d9094501425085859c60429163c2",
  "account_id": 268786704340,
  "name": "google"
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
  "identity_id": "e151cba136214be98b2d1a02e797db60",
  "account_id": 268786704340,
  "identity_source_id": "1da1d9094501425085859c60429163c2",
  "identity_type": "user",
  "name": "nicolagallo"
}
```

## Role

A `Role` is an identity within an account with associated permissions.
A role can be temporaraly assumed by a `Principal` identity.

```json
{
  "identity_id": "804ecc6b562242069c7837f63fd1a3b3",
  "account_id": 268786704340,
  "identity_source_id": "1da1d9094501425085859c60429163c2",
  "identity_type": "role",
  "name": "branch-manager"
}
```
