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

An `identity` is a unique entity that represents either a **user** or an **actor**.

{{< callout context="note" icon="info-circle" >}}
In the [MagicFarmacia sample](/docs/0.1/getting-started/adoption-through-example#integration-use-case-pharmacy-branch-management), multiple users and actors represent different branches and roles within the pharmacy, such as the `pharmacist` actor.

Additionally, the example includes two identity sources: `Google` and `Facebook`.
{{< /callout >}}

Identities are linked to identity sources.

```json
{
  "name": "google"
}
```

## Principal

A `Principal` is a human user or workload with granted permissions that authenticates and makes requests. It can be:

- A user
- An actor
- An assumed actor (a user acting as an actor or a workload assuming an actor)

## User

A `User` is an identity representing a single person or **Function Identifier (FID)** with specific permissions.

The name can be either a valid **PermGuard** name or an email address.

```json
{
  "identity_type": "user",
  "name": "nicolagallo"
}
```

## Actor

An `Actor` is a virtual identity that a **Principal** can temporarily assume. It can represent:

- A **Role**: A predefined set of permissions for specific tasks, such as `"Approvals Manager"` or `"Compliance Reviewer"`.
- A **Digital Twin**: A virtual representation of a user or service designed to perform tasks independently while reflecting the original identity.

**PermGuard** allows systems to **optionally** adopt the Actor model, ensuring that every operation is executed under the specific permissions of the **Actor**, rather than the broader permissions of the **Principal**.

### Benefits of the Actor Model

1. **Zero Trust Security**: Requires elevation into an Actor, ensuring only the necessary permissions are used for a task, reducing risk and ensuring full traceability.
2. **Role Isolation**: Limits each Actor to its assigned role or context, preventing unnecessary access and ensuring clear separation of responsibilities.
3. **Future Federation**: Provides a foundation for secure collaboration across organizations. Defined roles and permissions allow **PermGuard** to support federated systems where multiple organizations can work together while maintaining security boundaries.

This model enhances **security, flexibility, and scalability**, making it ideal for **distributed systems** and **multi-organization environments**.

```json
{
  "identity_type": "actor",
  "name": "branch-manager"
}
```
