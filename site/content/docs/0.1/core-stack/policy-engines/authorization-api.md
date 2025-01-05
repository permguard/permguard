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
  The store containing the policies used to evaluate the request. It includes a `type`, and `id`. The payload is designed to support different types of policy stores, including those that are immutable and versioned, to address various requirements.

- **`entities`**:
  Objects represent principals, subjects, actions, and resources. The payload supports multiple policy engines, each with its own entity schema. Entities are defined using a `schema` name and a list of `items` that adhere to this schema. Integration with a Policy Information Point (PIP) has to enable additional entities to be merged with those included in the request.

- **`subject`, `resource`, `action`, `context`**:
  These elements describe the subject (the entity requesting access), the resource (the entity being accessed), the action (the operation performed on the resource), and the context (the temporal details of the request). These elements aim to align with widely recognized authorization specifications such as [OpenID AuthZEN](https://openid.net/wg/authzen/specifications/).

- **`evaluations`**:
  The evaluations represent a list of access requests that a principal can perform to evaluate multiple access decisions within the scope of a single message exchange, acting on behalf of other subjects (a process also referred to as "boxcarring" requests).

{{< callout context="note" icon="info-circle" >}}
**Permguard** follows Zero Trust principles, and the Authorization API is built the same way. The principal can send authorization requests only for subjects it is allowed to act on.

Normally, the principal can specify only subjects linked to its identity. However, it can act for other subjects if it has permission, for example, when a subject gives delegation to the principal to act on its behalf.

If the principal does not have permission to act on a subject, the request will return an error to block unauthorized actions.

The main idea of passing the principal with its access token is to protect against certain types of attacks, including:

1. Authorization Inference Attack
2. Excessive Data Exposure
3. Side-Channel Attack on Authorization
4. Privilege Escalation

This approach makes the PDP more secure by ensuring that information is not exposed to the PEP unless it is within the authorized context. It also supports the concept of trusted delegation, allowing principals to act on behalf of others securely when permitted.
{{< /callout >}}

### Response Payload

The response payload includes the following elements:

- **`decision`**:
  The decision element specifies whether the request is allowed or denied. The decision is a boolean value (`true` or `false`).
- **`context`**:
  The context element provides additional information about the decision, including the reason for the decision. The context includes an `id` and `reason_admin` and `reason_user` objects. The `reason_admin` object contains information for the administrator, while the `reason_user` object contains information for the user.

### Simple Message Exchange

Here a simple example of a message exchange between the `PEP` and the `PDP`.

**Request Payload**:

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
  "action": {
    "name": "MagicFarmacia::Platform::Action::view",
    "properties": {}
  },
  "context": {
    "isSuperUser": true
  }
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
      "message": "Request failed policy 3df18a05380d4ddab164e6b8e82bd37b"
    },
    "reason_user": {
      "code": "403",
      "message": "Access denied due to insufficient privileges. Please contact your administrator."
    }
  }
}
```

### Message Exchange with Evaluations

Here an example of a message exchange with evaluations between the `PEP` and the `PDP`.

**Request Payload**:

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
  "evaluations": [
    {
      "subject": {
        "type": "user",
        "id": "amy.smith@acmecorp.com",
        "source": "keycloak",
        "properties": {}
      },
      "resource": {
        "type": "Magicfarmacia::Platform::BranchInfo",
        "id": "subscription",
        "properties": {
          "branch": {
            "id": "96902499c04246f0bbe8f2e67a165a64"
          }
        }
      },
      "action": {
        "name": "MagicFarmacia::Platform::Action::view",
        "properties": {}
      },
      "context": {
        "isSuperUser": true
      }
    },
    {
      "subject": {
        "type": "user",
        "id": "amy.smith@acmecorp.com",
        "source": "keycloak",
        "properties": {}
      },
      "resource": {
        "type": "Magicfarmacia::Platform::BranchInfo",
        "id": "subscription",
        "properties": {
          "branch": {
            "id": "96902499c04246f0bbe8f2e67a165a64"
          }
        }
      },
      "action": {
        "name": "MagicFarmacia::Platform::Action::delete",
        "properties": {}
      },
      "context": {
        "isSuperUser": true
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

### Message Exchange with Evaluations and Defaults

Here an example of a message exchange with evaluations and defaults between the `PEP` and the `PDP`.

**Request Payload**:

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
