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

An `identity` is an unique entity that represents either an **user** or a **actor**.

{{< callout context="note" icon="info-circle" >}}
In the context of the [MagicFarmacia sample](/docs/0.1/getting-started/adoption-through-example#integration-use-case-pharmacy-branch-management), there would be multiple users and actors representing the various branches and positions within the pharmacy, such as the `pharmacist` actor.

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
- An actor
- An assumed actor (actor assumed by a user or an actor assumed by a workload).

## User

An `User` is an identity representing a single person or FID (Function Identifier) that has specific permissions.

The name of the can be either a valid PermgGuard name or an email address.

```json
{
  "identity_type": "user",
  "name": "nicolagallo"
}
```

## Actor

An `Actor` is a type of virtual identity that can be temporarily assumed by a Principal identity. It represents either:

- A `Role`: A predefined set of permissions tailored to specific tasks, such as "Approvals Manager" or "Compliance Reviewer."
- A `Digital Twin`: A virtual representation of a user or service account, designed to perform tasks independently while reflecting the original identity.

PermGuard allows systems to **optionally** build around the concept of Actors. This approach isolates different profiles of an identity, ensuring every operation is executed under the specific permissions of the Actor rather than the broader permissions of the `Principal`.

1. `Zero Trust Security`: By requiring elevation into an Actor, only the permissions needed for a specific task are used, reducing risks and ensuring complete traceability.

2. `Role Isolation`: Each Actor is limited to its assigned role or context, creating clear separation between different responsibilities or operations.

3. `Future Federation`: The Actor model provides a strong foundation for enabling secure collaboration across organizations. With clearly defined roles and permissions, PermGuard supports federated systems where multiple organizations can work together while maintaining security boundaries.

This design enhances `security`, `flexibility`, and `scalability`, making it an ideal choice for distributed systems and multi-organization environments.

```json
{
  "identity_type": "actor",
  "name": "branch-manager"
}
```
