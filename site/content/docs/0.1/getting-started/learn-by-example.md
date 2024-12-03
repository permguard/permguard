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

### Policy and Permissions Definition

The first step is to define a policy and associate it with a role by specifying the required permissions.

```cedar  {title="magicfarmacia.cedar"}
permit(
    principal in Role::"administer-platform-branches",
    action in Action::"create",
    resource in Resource::"pharmacy-branch"
);
```

### Performing Permission Evaluation

After creating and associating the policy with the role, the next step is to perform the permission evaluation within the application.

```python  {title="app.py"}
has_permissions = permguard.check("permguard@localhost/581616507495/default/authn/identity/role/pharmacist", "magicfarmacia", "inventory", "view")

if has_permissions:
    print("Role can view inventory")
else:
    print("Role cannot view inventory")
```
