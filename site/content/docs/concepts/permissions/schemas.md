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
In `Permguard`, multiple repositories can be created, and each of them has a single **schema**. This provides a structured method for modelling the authorization model.

{{< callout context="note" icon="info-circle" >}}
In the context of the [MagicFarmacia sample](/docs/overview/adoption-through-example#integration-use-case-pharmacy-branch-management), , the schema primarily represents two domains: the `platform` tenant, which serves as the master tenant capable of managing all branches, and the `pharmacy branch` tenant.

The platform implements features to create a new tenant for each branch, which can be accomplished using the internal Permguard API.
{{< /callout >}}

## Schema
A schema serves as a logical representation, organizing resources and actions, and also includes metadata annotations.

## Domain
Additionally, a schema can be further subdivided into domains, offering enhanced granularity in resource management. A domain provides another level of logical representation, particularly advantageous for schemas employing a `Domain-Driven Design` (`DDD`) approach. By structuring schemas into domains, users can streamline development efforts and ensure architectural coherence.

```json
{
  "name": "magicfarmacia",
  "description": "Manage a pharmacy with multiple branches",
  "resources": []
}
```

In more details, each domain can define multiple **resources** and corresponding **actions** that can be performed on those resources.

{{< callout context="caution" icon="alert-triangle" >}}
It's important to note that creating a `Resource` for every entity within the application is not mandatory, the same concept applies for `Actions`.
However, it is advisable to create a Resource and an Action for each entity that requires modeling within the context of authorization.
Typically, fewer Resources and Actions are modeled compared to the entities in the application to prevent tightly coupled authorization layers.
{{< /callout >}}

## Resource
A **Resource** serves as the central entity within `Permguard`. It represents a logical entity within the application that must be enriched with authorization policies.

When creating authorization Resources, it's essential to consider `performance` and execution time required by the application to evaluate policies. This ensures optimal performance and efficient policy evaluation within the application context.

In summary, `Resources` in Permguard provide a structured approach to managing authorization policies, promoting flexibility and performance optimization within the application ecosystem.

```json
{
  "name": "inventory",
  "description": "Pharmacy inventory",
  "actions": []
}
```

## Action
An **action** is a specific operation that can be performed on a resource. Actions are used to define the operations that can be performed on a resource, such as `read`, `write`, `delete`, and `list`.

```json
{
  "name": "access",
  "description": "Access inventory"
}
```
