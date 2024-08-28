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
To illustrate the integration process and demonstrate features throughout the documentation, we will use an example of a pharmacy, referred to as `MagicFarmacia`, which operates multiple branches across different cities.

## Integration Use Case: Pharmacy Branch Management

Below is a specific scenario where an identity representing a pharmacy manager requires access to inventory information across all branches.

### Policy and Permissions Definition

The first step is to define a policy and associate it with a role by specifying the required permissions.

```python
# Policy to access inventory across all branches.
policy accessinventory {
    resources = uur:581616507495:*:pharmacy-branch:inventory/*,
    actions = ra:inventory:access
}

# Defines permissions to read inventory information.
permission inventoryread {
    permit = [accessinventory],
    forbid = []
}

# Defines a role for the branch manager responsible for managing inventory.
role branchmanager {
  permissions = [inventoryread]
}
```

### Performing Permission Evaluation

After creating and associating the policy with the role, the next step is to perform the permission evaluation within the application.

```python
has_permissions = permguard.check("uur:581616507495:permguard:authn:identity/branch-manager", "magicfarmacia-v0.0", "inventory", "access")

if has_permissions:
    print("Role can access inventory")
else:
    print("Role cannot access inventory")
```
