---
title: "Schemas"
slug: "Schemas"
description: ""
summary: ""
date: 2023-08-21T22:44:09+01:00
lastmod: 2023-08-21T22:44:09+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "schemas-ab6eb415c219e46768473a83f413266e"
weight: 2302
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
In **Permguard**, multiple ledgers can be created, and each ledger might have a single **schema**.
This provides a structured way to model the authorization framework.

{{< callout context="note" icon="info-circle" >}}
In the [MagicFarmacia sample](/docs/0.1.x/getting-started/hands-on-examples#integration-use-case-pharmacy-branch-management),
the schema represents two main namespaces:

- The **`platform` tenant**, acting as the master tenant that manages all branches.
- The **`pharmacy branch` tenant**, representing individual branches.

The platform includes features to create a new tenant for each branch using **Permguard's internal API**.
{{< /callout >}}

## Schema

A **schema** is a logical structure used to organize **resources** and **actions**.
It also includes **metadata annotations** to enhance policy management.

## Namespace

A schema can be further divided into **namespaces**, adding more granularity to resource management.
Namespaces provide another layer of logical organization, especially useful for schemas designed with **Domain-Driven Design (DDD)** principles.

By structuring schemas into namespaces, developers can simplify development and maintain architectural consistency.

```json
{
  "name": "magicfarmacia",
  "description": "Manage a pharmacy with multiple branches",
  "resources": []
}
```

Each **namespace** can define multiple **resources** and the corresponding **actions** that can be performed on them.

{{< callout context="caution" icon="alert-triangle" >}}
It is not mandatory to create a `Resource` for every entity within a zone, and the same applies to `Actions`.
However, it is recommended to define a **Resource** and an **Action** for any entity that requires explicit authorization modeling.

Typically, fewer Resources and Actions are defined compared to the total number of entities in a zone.
This prevents authorization layers from becoming too tightly coupled with the application logic.
{{< /callout >}}

## Resource

A **Resource** is a key entity in **Permguard**. It represents a logical element within the zone that requires authorization policies.

When defining **Resources**, consider:

- **Performance**: Ensure policies are structured efficiently to minimize evaluation time.
- **Scalability**: Optimize policy execution within the zone for better performance.

In summary, `Resources` in **Permguard** help structure authorization policies, ensuring flexibility and optimized performance within a **zone ecosystem**.

```json
{
  "name": "inventory",
  "description": "Pharmacy inventory",
  "actions": []
}
```

## Action

An **Action** is a specific operation that can be performed on a **Resource**.
Actions define what operations are allowed, such as:

- `read`
- `write`
- `delete`
- `list`

These actions help enforce precise authorization rules, ensuring that only permitted operations can be executed on a resource.

```json
{
  "name": "access",
  "description": "Access inventory"
}
```
