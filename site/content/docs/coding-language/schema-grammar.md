---
title: "Schema Grammar"
slug: "Schema Grammar"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "schema-grammar-f68ed4d511834c2db6a8d1055f56c807"
weight: 4002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

A schema is a structured representation that defines how domains, resources, and actions are organized. This schema is used to model the application authorization model and serves as the foundation for setting up and enforcing policies across the target application. Below is an explanation of each element and the rules for composing a schema.

{{< callout context="note" icon="info-circle">}}
It is important to note that a schema is evaluated to verify the correctness of the policies only if strict evaluation is required.
{{< /callout >}}


Below is a sample schema:


```yaml
domains:
  - name: platform
    description: Platform-level operations
    resources:
      - name: pharmacy-branch
        actions:
          - name: create
            description: Create new pharmacy branch
          - name: update
            description: Update existing pharmacy branch
          - name: delete
            description: Delete pharmacy branch
  - name: pharmacy-branch
    description: Pharmacy branch-level operations
    resources:
      - name: staff
        actions:
          - name: view
            description: view staff details
          - name: manage
            description: Manage staff details
          - name: assign_roles
            description: Assign roles to staff members
      - name: inventory
        actions:
          - name: view
            description: View inventory items
          - name: manage
            description: Manage inventory, including stock levels and product details
          - name: order
            description: Order new stock for the pharmacy
      - name: orders
        actions:
          - name: view
            description: View customer orders
          - name: manage
            description: Manage customer orders
          - name: orders
            description: Place a new order for a customer
```

## Domains

A domain represents a broad category or functional area within the system. It is the top-level organizational unit in a schema. Domains encapsulate related resources and define the scope within which specific operations are applied.

- Naming: Each domain must have a unique name that clearly reflects its purpose or the area it governs.
- Description: Optionally, a domain can include a description that provides additional context or clarification about its role.

```yaml
domains:
  - name: platform
    description: Platform-level operations
  - name: pharmacy-branch
    description: Operations specific to individual pharmacy branches
```

## Resources

A resource represents an entity or object within a domain that is subject to various actions. Resources are the specific items that policies and operations are applied to within a domain.

- Naming: Each resource within a domain must have a unique name. This name should accurately describe the resource.
- Description: Like domains, resources can include an optional description to further explain their role.

```yaml
resources:
  - name: pharmacy-branch
  - name: staff
  - name: inventory
  - name: orders
  - name: reports
```

## Actions
An action represents an operation that can be performed on a resource. Actions define the permissible activities or methods that users or systems can execute within the scope of a resource.

- Naming: Each action within a resource must have a unique name. The name should be a verb or verb phrase that clearly indicates the operation (e.g., "view", "manage", "create").
- Description: Actions can include an optional description that elaborates on what the action does.

```yaml
actions:
  - name: create
    description: Create a new pharmacy branch
  - name: view
    description: View staff details
  - name: manage
    description: Manage inventory, including stock levels
```

## Rules of Composition

When composing a schema, the following rules must be observed:

- Unique Names: Each domain, resource, and action must have a unique name within its context to avoid conflicts and ensure clarity. The naming of the schema must also adhere to the established PermGuard naming conventions.
- Hierarchical Structure: The schema must be structured hierarchically, with domains at the top level, followed by resources within each domain, and actions within each resource.
- Optional Descriptions: While descriptions are optional, they are recommended for enhancing the clarity and maintainability of the schema.
- Mandatory Names: The name field is mandatory for every domain, resource, and action. This ensures that each element is properly identified and can be referenced in policies.

Below is the JSON schema used to validate the schema:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "domains": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "description": {
            "type": "string"
          },
          "resources": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "name": {
                  "type": "string"
                },
                "actions": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "name": {
                        "type": "string"
                      },
                      "description": {
                        "type": "string"
                      }
                    },
                    "required": ["name"]
                  }
                }
              },
              "required": ["name"]
            }
          }
        },
        "required": ["name"]
      }
    }
  },
  "required": ["domains"]
}
```
