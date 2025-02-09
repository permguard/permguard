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
weight: 5201
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The **Authorization API** allows the `Policy Enforcement Point` (`PEP`) and the `Policy Decision Point` (`PDP`) to communicate. The `PEP` sends authorization requests, and the `PDP` responds with decisions. They do not need to know how the other works internally.

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
**PermGuard** enables Zero Trust principles, and the Authorization API follows the same approach. The `principal` can send an authentication token along with the authorization request. This allows enforcing Zero Trust security by validating the token and ensuring that the `principal` is allowed to act on behalf of the `subject`, for example, in the context of trusted elevation and trusted delegation.

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

## Sample Message Exchange

Here an example of a message exchange with evaluations and defaults between the `PEP` and the `PDP`.

**Request Payload**:

```json
{
  "authorization_context": {
    "zone_id": 268786704340,
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
            "type": "MagicFarmacia::Platform::Subscription",
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
    "type": "MagicFarmacia::Platform::Subscription",
    "id": "e3a786fd07e24bfa95ba4341d3695ae8",
    "properties": {}
  },
  "context": {
    "time": "2025-01-23T16:17:46+00:00"
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

**Response Payload**:

```json
{
  "decision": false,
  "context": {
    "id": "e91df3711cb046f18c7576303dbeccda",
    "reason_admin": {
      "code": "403",
      "message": "Request failed because of evaluations."
    },
    "reason_user": {
      "code": "403",
      "message": "Access denied due to insufficient privileges. Please contact your administrator."
    }
  },
  "evaluations": [
    {
      "decision": false,
      "context": {
        "id": "e91df3711cb046f18c7576303dbeccda",
        "reason_admin": {
          "code": "403",
          "message": "Request failed policy 3df18a05380d4ddab164e6b8e82bd37b"
        },
        "reason_user": {
          "code": "403",
          "message": "Access denied due to insufficient privileges. Please contact your administrator."
        }
      }
    },
    {
      "decision": false,
      "context": {
        "id": "83628fb761fc4622aaf2f70c5338093c",
        "reason_admin": {
          "code": "403",
          "message": "Request failed policy 78df7ffa88a44795bac156339ae1d0da"
        },
        "reason_user": {
          "code": "403",
          "message": "Access denied due to insufficient privileges. Please contact your administrator."
        }
      }
    }
  ]
}
```
