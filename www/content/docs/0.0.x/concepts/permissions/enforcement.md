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
weight: 2306
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
In **Permguard**, enforcement is handled by the **Policy Enforcement Point (PEP)**.
Its role is to verify whether an `identity` has permission to perform specific `actions` on `resources` within a given `namespace`.

{{< callout context="note" icon="info-circle" >}}
In the [ZTMedFlow sample](/docs/0.0.x/getting-started/hands-on-example/), the application enforces different types of permission checks.
{{< /callout >}}

## Enforcement

To enforce access control, the **PEP** queries the **Policy Decision Point (PDP)** for a decision.

```json
{
  "authorization_model": {
    "zone_id": 273165098782,
    "policy_store": {
      "kind": "ledger",
      "id": "fd1ac44e4afa4fc4beec622494d3175a"
    },
    "principal": {
      "type": "user",
      "id": "amy.smith@acmecorp.com",
      "source": "keycloak"
    },
    "entities": {
      "schema": "cedar",
      "items": [
        {
          "uid": {
            "type": "ZTMedFlow::Platform::Subscription",
            "id": "e3a786fd07e24bfa95ba4341d3695ae8"
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
    "properties": {
      "isSuperUser": true
    }
  },
  "resource": {
    "type": "ZTMedFlow::Platform::Subscription",
    "id": "e3a786fd07e24bfa95ba4341d3695ae8",
    "properties": {}
  },
  "context": {
    "time": "2025-01-23T16:17:46+00:00"
  },
  "evaluations": [
    {
      "action": {
        "name": "ZTMedFlow::Platform::Action::create",
        "properties": {}
      }
    },
    {
      "action": {
        "name": "ZTMedFlow::Platform::Action::delete",
        "properties": {}
      }
    }
  ]
}
```
