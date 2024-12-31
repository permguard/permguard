---
title: "Enforcement"
slug: "Enforcement"
description: ""
summary: ""
date: 2023-08-01T00:25:01+01:00
lastmod: 2023-08-01T00:25:01+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "enforcement-f9bdc944c7cb7b27eea146c4f8ef46c3"
weight: 2305
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

In **Permguard**, enforcement is ensured by the Policy Enforcement Point (PEP). Its intent is to verify if an identity can execute certain actions on certain resources and namespaces.

{{< callout context="note" icon="info-circle" >}}
In the context of the [MagicFarmacia sample](/docs/0.1/getting-started/adoption-through-example#integration-use-case-pharmacy-branch-management), the application would enforce a permission check on the `pharmacist` actor to determine if it has `view access` to the inventory within the context of the `matera-branch` and `pisa-branch` tenants.
{{< /callout >}}

## Enforcement

To complete the enforcement process, the PEP queries the Policy Decision Point (PDP).

```json
{
  "authorization_context": {
    "policy_store": {
      "type": "ledger",
      "id": "magicfarmacia",
      "version": "722164f552f2c8e582d4ef79270c7ec94b3633e8172af6ea53ffe1fdf64d66de"
    },
    "principal": {
      "type": "user",
      "id": "john.smith@acmecorp.com",
      "source": "keycloak",
      "tokens": {
        "identity_token": "eyJhbGciOiJI...",
        "access_token": "eyJhbGciOiJI..."
      }
    },
    "entities": {
      "schema": "cedar",
      "items": [
        {
          "uid": {
            "type": "Branch",
            "id": "96902499c04246f0bbe8f2e67a165a64"
          },
          "attrs": {
            "name": "Milan Office"
          },
          "parents": []
        }
      ]
    }
  },
  "subject": {
    "type": "user",
    "id": "john.smith@acmecorp.com",
    "source": "keycloak",
    "properties": {}
  },
  "context": {
    "time": "2024-12-26T23:02-45:00"
  },
  "evaluations": [
    {
      "resource": {
        "type": "employee",
        "id": "8796159789",
        "properties": {
          "branch": {
            "id": "96902499c04246f0bbe8f2e67a165a64"
          }
        }
      },
      "action": {
        "name": "assignRole",
        "properties": {}
      }
    }
  ]
}
```
