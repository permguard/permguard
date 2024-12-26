---
title: "Authorization API"
slug: "Authorization API"
description: ""
summary: ""
date: 2024-12-26T22:53:00+01:00
lastmod: 2024-12-26T22:53:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authorization-api-ceea086189c54d57a2f17e0586920c8e"
weight: 8202
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The **Authorization API** establishes the communication model between the `Policy Enforcement Point` (`PEP`) and the `Policy Decision Point` (`PDP`), enabling them to exchange authorization requests and decisions without requiring knowledge of each other's internal workings.

## Payload

The payload specifies the structure of the data exchanged between the `PEP` and the `PDP`.

### Request Payload

The request payload includes the following elements:

- **`principal`**:
  The identity of the user or system making the request. For instance, in a web application acting as a PEP, the principal is the authenticated user sending the API request. The principal is represented by an `identity_token` and an `access_token`. This is distinct from the API-Key used to authenticate the PEP with the PDP.

- **`policy_store`**:
  The store containing the policy used to evaluate the request. It includes a `type`, an `id`, and a `version`. The system is designed to support different types of policy stores, including those that are immutable and versioned, to address various requirements.

- **`entities`**:
  Objects represent principals, subjects, actions, and resources. The system supports multiple policy engines, each with its own entity schema. Entities are defined using a `schema` name and a list of `items` that adhere to this schema. Integration with a Policy Information Point (PIP) enables additional entities to be merged with those included in the request.

- **`subject`, `resource`, `action`, `context`**:
  These elements describe the subject (the entity requesting access), the resource (the entity being accessed), the action (the operation performed on the resource), and the context (the temporal details of the request). These elements aim to align with widely recognized authorization specifications such as [OpenID AuthZEN](https://openid.net/wg/authzen/specifications/).

{{< callout context="note" icon="info-circle" >}}
**Permguard** follows Zero Trust principles, and the Authorization API is built the same way. The principal can send authorization requests only for subjects it is allowed to act on.

Normally, the principal can specify only subjects linked to its identity. However, it can act for other subjects if it has permission, for example, when a subject gives delegation to the principal to act on its behalf.

If the principal does not have permission to act on a subject, the request will return an error to block unauthorized actions.
{{< /callout >}}

An example `REQUEST` payload illustrating the subject, resource, action, and temporal context.

```json
{
  "principal": {
    "identity_token": "string",
    "access_token": "string"
  },
  "policy_store": {
    "type": "ledger",
    "id": "string",
    "version": "string"
  },
  "entities": {
    "schema": "cedar",
    "items": [
      {
        "uid": { "type": "Branch", "id": "96902499c04246f0bbe8f2e67a165a64" },
        "attrs": { "name": "Milan Office" },
        "parents": []
      }
    ]
  },
  "subject": {
    "type": "user",
    "id": "john.smith@acmecorp.com",
    "source": "keycloak",
    "properties": {}
  },
  "resource": {
    "type": "employee",
    "id": "8796159789",
    "properties": {
      "branch": {
        "id": "265498168"
      }
    }
  },
  "action": {
    "name": "assignRole",
    "properties": {}
  },
  "context": {
    "time": "2024-12-26T23:02-45:00"
  }
}
```

### Response Payload

An example `RESPONSE` payload containing the authorization decision, contextual information for administrators, and localized error messages for users.

```json
{
  "decision": true,
  "context": {
    "id": "e91df3711cb046f18c7576303dbeccda",
    "reason_admin": {
      "en": "Request failed policy 24a422fd0fcf454b8e2d4f13e98cce2b"
    },
    "reason_user": {
      "en-403": "Access denied due to insufficient privileges. Please contact your administrator.",
      "it-403": "Accesso negato a causa di privilegi insufficienti. Si prega di contattare il proprio amministratore."
    }
  }
}
```
