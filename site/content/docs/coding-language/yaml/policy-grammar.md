---
title: "Policy Grammar"
slug: "Policy Grammar"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "policy-grammar-6f7551118a914e7392a1acd29b1ef521"
weight: 4101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

When creating a policy, it’s essential to follow the proper structure and naming conventions to ensure consistency and correctness. Below is a guide to creating a policy, using the example provided.

Policies can be created in yaml files within the root of the working directory.

Below is a sample directory structure that includes the schema file and sample policy files:

```plaintext
.
├── .permguard
├── schema.yml
├── staff_policies.yml
├── inventory_policies.yml
```

Here is an example policy for managing inventory:

```yaml
name: manage-inventory
actions:
  - inventory:access
  - inventory:manage
resources:
  - uur::::pharmacy-branch:inventory/*
```

## Rules of Composition

A policy is composed of three main elements: name, actions, and resources.

- `name`: The unique identifier for the policy. It should be descriptive and adhere to the established PermGuard naming conventions.
- `actions`: This section defines the specific operations that the policy allows on the resources. Actions must use the RA (Resource Action) naming convention. Each action is written in the format `{resource}`:``{action}``, where:
  - `{resource}` represents the type of resource being acted upon.
  - ``{action}`` specifies the operation allowed on the resource.
- resources: This section lists the resources that the policy applies to. Resources must be specified using the UUR (Universally Unique Resource) naming convention. The UUR format ensures precise identification of resources across different domains, tenants, and accounts.

Below is the JSON schema used to validate the policy:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "name": {
      "type": "string"
    },
    "actions": {
      "type": "array",
      "items": {
        "type": "string",
      }
    },
    "resources": {
      "type": "array",
      "items": {
        "type": "string",
      }
    }
  },
  "required": ["name", "actions", "resources"],
  "additionalProperties": false
}
```
