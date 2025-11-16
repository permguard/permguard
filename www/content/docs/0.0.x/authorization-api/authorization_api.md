---
title: "AuthZApi"
slug: "AuthZApi"
description: ""
summary: ""
date: 2024-12-26T22:53:00+01:00
lastmod: 2024-12-26T22:53:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authorization-api-ceea086189c54d57a2f17e0586920c8e"
weight: 5201
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The **AuthZApi** allows the `Policy Enforcement Point` (`PEP`) and the `Policy Decision Point` (`PDP`) to communicate. The `PEP` sends authorization requests, and the `PDP` responds with decisions. They do not need to know how the other works internally.

## Payload

The payload defines the format of the data shared between the `PEP` and the `PDP`.

### Request Payload

The request payload contains the following elements:

- **`principal`**:
  The identity of the user or system making the authorization request. This identity has been authenticated by the identity provider. The `principal` and the `subject` are often the same, but they can be different. The `principal` is represented by an `identity_token` and an `access_token`. This is different from the API key used to authenticate the `PEP` with the `PDP`.

- **`policy_store`**:
  The storage that holds the policies used to evaluate the request. It includes a `type` and an `id`. The policy store supports the ledger but is designed to be flexible, allowing other types of policy stores to be added as needed.

- **`entities`**:
  The payload supports multiple policy engines, each with its own entity schema. Entities are defined by a `schema` name and a list of `items` that follow this schema.

- **`subject`, `resource`, `action`, `context`**:
  These elements define the subject (who is requesting access), the resource (what is being accessed), the action (what operation is performed), and the context (time-related details of the request). These elements follow widely recognized authorization standards, such as [OpenID AuthZEN](https://openid.net/wg/authzen/specifications/).

- **`evaluations`**:
  A list of access requests that a `principal` can use to evaluate multiple access decisions in a single message exchange. This allows checking permissions for multiple subjects at once, a process also known as "boxcarring" requests.

{{< callout context="note" icon="info-circle" >}}
**Permguard** enables Zero Trust principles, and the AuthZApi follows the same approach. The `principal` can send an authentication token along with the authorization request. This allows enforcing Zero Trust security by validating the token and ensuring that the `principal` is allowed to act on behalf of the `subject`, for example, in the context of trusted elevation and trusted delegation.

If the `principal` does not have permission to act on a `subject`, the request will return an error to block unauthorized actions.

Passing the `principal` with its access token helps protect against specific types of attacks, including:

1. Authorization Inference Attack
2. Excessive Data Exposure
3. Side-Channel Attack on Authorization
4. Privilege Escalation

This approach makes the `PDP` more secure by ensuring that information is not exposed to the `PEP` unless it is within an authorized context. It also supports trusted delegation, allowing `principals` to act on behalf of others securely when permitted.
{{< /callout >}}

### Response Payload

The response payload includes the following elements:

- **`decision`**:
  The decision element specifies whether the request is allowed or denied. The decision is a boolean value (`true` or `false`).
- **`context`**:
  The context element provides additional information about the decision, including the reason for the decision. The context includes an `id` and `reason_admin` and `reason_user` objects. The `reason_admin` object contains information for the administrator, while the `reason_user` object contains information for the user.

## Sample Payloads

Here is an example of an **authorization request** and its response exchanged between the `PEP` and the `PDP`.

**Request Payload**:

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
            "type": "ZTMedFlow::Platform::BranchInfo",
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
  "request_id": "abc1",
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
    "properties": {
      "isEnabled": true
    }
  },
  "action": {
    "name": "ZTMedFlow::Platform::Action::create",
    "properties": {
      "isEnabled": true
    }
  },
  "context": {
    "time": "2025-01-23T16:17:46+00:00",
    "isSubscriptionActive": true
  }
}
```

**Response Payload**:

```json
{
  "request_id": "abc1",
  "decision": true,
  "context": {
    "id": "08bd6cc837ae4e7eb9ba37f31d5b355c"
  },
  "evaluations": [
    {
      "request_id": "abc1",
      "decision": true,
      "context": {
        "id": "08bd6cc837ae4e7eb9ba37f31d5b355c"
      }
    }
  ]
}
```
