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
    "application_id": 268786704340,
    "policy_store": {
      "type": "ledger",
      "id": "fd1ac44e4afa4fc4beec622494d3175a"
    },
    "principal": {
      "type": "user",
      "id": "amy.smith@acmecorp.com",
      "source": "keycloak",
      "identity_token": "eyJhbGciOiJI...",
      "access_token": "eyJhbGciOiJI..."
    },
    "entities": {
      "schema": "cedar",
      "items": [
        {
          "uid": {
            "type": "Permguard::IAM::User",
            "id": "amy.smith@acmecorp.com"
          },
          "attrs": {
          },
          "parents": []
        },
        {
          "uid": {
            "type": "Magicfarmacia::Platform::BranchInfo",
            "id": "subscription"
          },
          "attrs": {
            "active": true
          },
          "parents": []
        }
      ]
    }
  },
  "subject": {
    "type": "user",
    "id": "amy.smith@acmecorp.com",
    "source": "keycloak",
    "properties": {}
  },
  "resource": {
    "type": "Magicfarmacia::Platform::BranchInfo",
    "id": "subscription",
    "properties": {}
  },
  "context": {
    "isSuperUser": true
  },
  "evaluations": [
    {
      "action": {
        "name": "MagicFarmacia::Platform::Action::view",
        "properties": {}
      }
    },
    {
      "action": {
        "name": "MagicFarmacia::Platform::Action::delete",
        "properties": {}
      }
    }
  ]
}
```
