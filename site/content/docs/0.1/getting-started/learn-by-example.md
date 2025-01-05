---
title: "Learn by Example"
slug: "Learn by Example"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "adoption-through-example-8c89ddc8339f83444fc4b97264bd5c45"
weight: 1005
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
To illustrate the integration process and demonstrate features throughout the documentation, we will use an example of a pharmacy, referred to as `MagicFarmacia`, which operates multiple branches across different cities.

## Integration Use Case: Pharmacy Branch Management

Below is a specific scenario where an identity representing a pharmacy manager requires access to inventory information across all branches.

## Policy and Permissions Definition

The first step is to define a policy and associate it with an actor by specifying the required permissions.

```cedar  {title="magicfarmacia.cedar"}
@id("platform-administrator")
permit(
  principal == Permguard::IAM::Actor::"platform-admin",
  action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"create", MagicFarmacia::Platform::Action::"update", MagicFarmacia::Platform::Action::"delete"],
  resource == MagicFarmacia::Platform::BranchInfo::"subscription"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-manager")
permit(
  principal == Permguard::IAM::Actor::"platform-manager",
  action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"update"],
  resource == MagicFarmacia::Platform::BranchInfo::"subscription"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-auditor")
permit(
  principal == Permguard::IAM::Actor::"platform-auditor",
  action == MagicFarmacia::Platform::Action::"view",
  resource == MagicFarmacia::Platform::BranchInfo::"subscription"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-superuser")
permit(
  principal,
  action == MagicFarmacia::Platform::Action::"view",
  resource == MagicFarmacia::Platform::BranchInfo::"subscription"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};
```

## Performing Permission Evaluation

After creating and associating the policy with the actor, the next step is to perform the permission evaluation within the application.

```python  {title="app.py"}
has_permissions = permguard.check(principal, policy_store, entities, subject, resource, action, context)

if has_permissions:
    print("Actor can view inventory")
else:
    print("Actor cannot view inventory")
```
