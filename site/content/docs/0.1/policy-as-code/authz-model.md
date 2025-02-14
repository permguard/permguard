---
title: "AuthZ Model"
slug: "AuthZ Model"
description: ""
summary: ""
date: 2025-02-14T00:34:10+01:00
lastmod: 2025-02-14T00:34:10+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authz-model-2acc79fe1e014fe2ade6d301de843c14"
weight: 4002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The **authorization model** defines the AuthZ model data structure, which is derived by combining the Authorization API inputs with Policy-as-Code.

## Policy Store

The `policy store` is required to load policies, schemas, and other related data necessary to build the AuthZ model.

This is provided as an input to the Authorization API.

```json
{
  "authorization_model": {
    "zone_id": 694778299643,
    "policy_store": {
      "type": "ledger",
      "id": "3b72d00fb7d247848757fb37be8d0814"
    }
  }
}
```

The `Permguard` decision engine loads the policy storage based on the input type and ID existing in the input zone.

| PATH                                    | VALUES | DESCRIPTION                                                            |
|-----------------------------------------|--------|------------------------------------------------------------------------|
| authorization_model/zone_id           |        | A unique zone identifier distinguishes each input zone.                |
| authorization_model/policy_store/type | LEDGER | The Policy Store type defines the storage mechanism used for policies. |
| authorization_model/policy_store/id   |        | The unique identifier of the Policy Store.                             |

## Principal

The `Principal` is the entity performing the action being authenticated, with the authority to act on behalf of the `Subject`.
While the `Principal` and `Subject` are usually the same, there are scenarios where the `Principal` is not the same of the `Subject`.

```json
{
  "authorization_model": {
    "principal": {
      "type": "user",
      "id": "amy.smith@acmecorp.com",
      "source": "keycloak",
      "identity_token": "eyJhbGciOiJI...",
      "access_token": "eyJhbGciOiJI..."
    }
  }
}
```

## Entities

The `Entities` object is a `set of attributes` that represent policy's entities.

```json
{
  "authorization_model": {
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
  }
}
```

## Subject

The Subject specifies the entity requesting access to a resource.

- `type`: A required string value that specifies the type of the Subject.
- `id`: A required string value containing the unique identifier of the Subject, scoped to the type.
- `source`: An optional string value that specifies the source of the Subject.
- `properties`: An optional JSON object containing any number of key-value pairs, which can be used to express additional properties of a Subject.

```json
{
  "type": "user",
  "id": "alice",
  "source": "keycloak",
  "properties": {
    "department": "sales"
  }
}
````

## Resources

The `Resource` specifies the entity requesting access to a resource.

- `type`: A required string value that specifies the type of the Resource.
- `id`: A required string value containing the unique identifier of the Resource, scoped to the type.
- `properties`: An optional JSON object containing any number of key-value pairs, which can be used to express additional properties of a Resource.

```json
{
  "type": "MagicFarmacia::Platform::Account::Subscription",
  "id": "e3a786fd07e24bfa95ba4341d3695ae8",
  "properties": {
    "active": true
  }
}
````

## Action

The `Action` specifies the entity requesting access to a action.

- `name`: A required string value that specifies the name of the Action.
- `properties`: An optional JSON object containing any number of key-value pairs, which can be used to express additional properties of a Action.

```json
{
  "type": "cancel",
  "properties": {
    "reason": "expired subscription"
  }
}
````

## Context

The `Context` object is a set of attributes that represent environmental or contextual data about the request such as time of day. It is a JSON [RFC8259](https://www.rfc-editor.org/rfc/rfc8259) object.

```json
{
  "expire_at": "2024-12-26T22:53:00+01:00",
}
````
