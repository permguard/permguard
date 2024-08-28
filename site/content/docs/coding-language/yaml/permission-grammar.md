---
title: "Permission Grammar"
slug: "Permission Grammar"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "policy-grammar-6f7551118a914e7392a1acd29b1ef521"
weight: 4102
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

When creating a permission, it’s essential to follow the proper structure and naming conventions to ensure consistency and correctness. Below is a guide to creating a permission, using the example provided.

Permissions can be created in YAML files within the root of the working directory.

```plaintext
.
├── .permguard
├── schema.yml
├── staff-permissions.yml
├── staff-policies.yml
├── inventory-permissions.yml
├── inventory-policies.yml
```

Here is an example permission for read-only access to inventory:

```yaml
name: inventory-read
permit:
  - access-inventory
fobid:
  - manage-inventory
```

## Rules of Composition

A permission is composed of three main elements: name, permit, and forbid.

- `name`: The unique identifier for the permission. It should be descriptive and adhere to the established PermGuard naming conventions.
- `permit`: This section lists the names of valid policies that the permission explicitly allows. Each entry in the permit section must reference an existing policy that defines the specific actions and resources that are permitted under this permission. It’s crucial to ensure that only valid and correctly defined policies are included here.
- `forbid`: This section lists the names of valid policies that are explicitly prohibited by this permission. Even if these policies might be permitted by other permissions, they will be overridden and denied by the forbid list. This ensures that certain actions or access are strictly restricted according to the requirements.

{{< callout context="caution" icon="alert-triangle" >}}
The `forbid` section takes precedence over `permit`. This means that if a policy is listed in both permit and forbid, the actions allowed by the permit will be overridden and denied by the forbid. Therefore, any permissions granted in permit are effectively canceled if they are also specified in forbid.
{{< /callout >}}

Below is the JSON schema used to validate the permission:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "name": {
      "type": "string"
    },
    "permit": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "forbid": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  },
  "required": ["name", "permit"],
  "additionalProperties": false
}
```
