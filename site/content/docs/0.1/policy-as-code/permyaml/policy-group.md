---
title: "Policy Group Grammar"
slug: "Policy Group Grammar"
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
A `Policy Group` is a special construct in PermYaml that allows grouping multiple policies together. These groups can then be referenced as a single entity in permissions assigne

When creating a policy group, it’s essential to follow the proper structure and naming conventions to ensure consistency and correctness. Below is a guide to creating a policy group, using the example provided.

Policy groups can be created in YAML files within the root of the working directory.

Below is a sample directory structure that includes schema, policies, and policy groups files:

```plaintext
.
├── .permguard
├── schema.yml
├── staff_policy groups.yml
├── staff_policies.yml
├── inventory_policy groups.yml
├── inventory_policies.yml
```

Here is an example policy group for read-only access to inventory:

```yaml
---
name: inventory-read
policies:
  - access-inventory
  - manage-inventory
```

## Rules of Composition

A policy group is composed of two main elements: name, policies.

- `name`: The unique identifier for the policy group. It should be descriptive and adhere to the established Permguard naming conventions.
- `policies`: This section lists the names of the policies to be grouped together.

Below is the JSON schema used to validate the policy group:

```json
{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "name": {
      "type": "string"
    },
    "policies": {
      "type": "array",
      "items": [
        {
          "type": "string"
        },
        {
          "type": "string"
        }
      ]
    }
  },
  "required": [
    "name",
    "policies"
  ]
}
```
