---
title: "Hands-on Examples"
slug: "Hands-on Examples"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "hands-on-examples-8c89ddc8339f83444fc4b97264bd5c45"
weight: 1005
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
To explain the integration process and showcase features in this documentation, we will use an example of a pharmacy called `MagicFarmacia`, which has multiple branches in different cities.

## Integration Use Case: Pharmacy Branch Management

In this scenario, a pharmacy manager needs access to inventory information across all branches.

## Policy and Permissions Definition

The first step is to create a policy and assign it to an actor by defining the necessary permissions.

```cedar  {title="magicfarmacia.cedar"}
@id("platform-administrator")
permit(
  principal in Permguard::IAM::Actor::"platform-admin",
  action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"create", MagicFarmacia::Platform::Action::"update", MagicFarmacia::Platform::Action::"delete"],
  resource == MagicFarmacia::Platform::Subscription::"e3a786fd07e24bfa95ba4341d3695ae8"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-manager")
permit(
  principal in Permguard::IAM::Actor::"platform-admin",
  action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"update"],
  resource == MagicFarmacia::Platform::Subscription::"e3a786fd07e24bfa95ba4341d3695ae8"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-auditor")
permit(
  principal in Permguard::IAM::Actor::"platform-auditor",
  action == MagicFarmacia::Platform::Action::"view",
  resource == MagicFarmacia::Platform::Subscription::"e3a786fd07e24bfa95ba4341d3695ae8"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};

@id("platform-superuser")
permit(
  principal,
  action == MagicFarmacia::Platform::Action::"view",
  resource == MagicFarmacia::Platform::Subscription::"e3a786fd07e24bfa95ba4341d3695ae8"
)
unless {
  principal has isSuperUser && principal.isSuperUser == false
};
```

## Performing Permission Evaluation

Once the policy is created and linked to the actor, the next step is to evaluate permissions within the application.

```python  {title="app.py"}
has_permissions = permguard.check(principal, policy_store, entities, subject, resource, action, context)

if has_permissions:
    print("Actor can view inventory")
else:
    print("Actor cannot view inventory")
```
