---
title: "Adoption Through Example"
slug: "Adoption Through Example"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "adoption-through-example-8c89ddc8339f83444fc4b97264bd5c45"
weight: 1003
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

`PermGuard` is a modern `Authorization Provider` that implements an advanced authorization layer. It delivers dynamic access control by managing user permissions, roles, and policies, ensuring secure and efficient authorization across diverse systems and applications.

## Infrastructure

PermGuard can be deployed in various environments, ranging from virtual machines to container orchestration systems like Kubernetes and beyond.

## Administration

PermGuard exposes gRPC endpoints for administrative functions, including the ability to create and manage:

- Accounts
- Tenants
- Identity Sources and Identities
- Schema (definitions for domains, resources, and actions)
- Policies
- Permissions.

## Identities

Since PermGuard does not include an authentication layer, it is crucial to integrate it with an Authentication Provider. This integration can be accomplished by importing users from the Authentication Provider using the available APIs and SDKs, or through manual processes via the PermGuard CLI.

Additionally, the application provides the capability to create and manage users on-the-fly through the available APIs and SDKs. It also supports the creation and management of roles.

## Integration

PermGuard integrates seamlessly with any application, whether deployed on **servers**, **containers**, or in **serverless** environments. Integration is facilitated through gRPC requests to the `Policy Decision Point`, and SDKs are available for various programming languages to ensure smooth implementation.


{{< callout context="note" icon="info-circle" >}}
A Policy Decision Point can be deployed close to the node, such as in a sidecar container. These proximity services synchronize with the remote PermGuard instance, ensuring low latency and high availability. `Permission evaluation` is performed in `approximately 1ms`.

{{< /callout >}}

There are two primary use cases for this integration:

- **API**: An endpoint accepts an authentication token (e.g., JWT) and evaluates if the associated identity has the necessary permissions for the requested operations.
- **Background**: A background process, such as a job or long-running worker, checks if the identity linked to the action has the required permissions. In a distributed system, this identity might be included in the message being processed.

For additional use cases, see [here](/docs/overview/patterns-through-use-cases).

## Integration Use Case: Pharmacy Branch Management

To illustrate the integration process and demonstrate features throughout the documentation, we will use an example of a pharmacy, referred to as `MagicFarmacia`, which operates multiple branches across different cities.

Below is a specific scenario where an identity representing a pharmacy manager requires access to inventory information across all branches.

### Policy and Permissions Definition

The first step is to define a policy and associate it with a role by specifying the required permissions.

```python
# Policy to access inventory across all branches.
policy AccessInventory {
    resources = uur:581616507495:default:pharmacy:inventory:branch/*,
    actions = ra:inventory:Access
}

# Defines permissions to read inventory information.
permission InventoryRead {
    permit = [AccessInventory],
    forbid = []
}

# Defines a role for the branch manager responsible for managing inventory.
role BranchManager {
  permissions = [InventoryRead]
}
```

### Performing Permission Evaluation

After creating and associating the policy with the role, the next step is to perform the permission evaluation within the application.

```python
has_permissions = permguard.check("uur:581616507495:permguard:identities:iam:role/branch-manager", "pharmacy/1.0.0", "Access", "inventory")

if has_permissions:
    print("Role can access inventory")
else:
    print("Role cannot access inventory")
```
