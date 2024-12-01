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

{{< callout context="note" icon="info-circle" >}}
In the context of the [MagicFarmacia sample](/docs/0.1/getting-started/adoption-through-example#integration-use-case-pharmacy-branch-management), there would be multiple users and roles representing the various branches and positions within the pharmacy, such as the `pharmacist` role.

Moreover, in the example, there are two sample identity sources: one for `Google` and one for `Facebook`.
{{< /callout >}}

Identities are linked to identity sources.

```json
{
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

The name of the can be either a valid PermgGuard name or an email address.

```json
{
  "identity_type": "user",
  "name": "nicolagallo"
}
```

## Role

A `Role` is an identity within an account with associated permissions.
A role can be temporaraly assumed by a `Principal` identity.

```json
{
  "identity_type": "role",
  "name": "branch-manager"
}
```
