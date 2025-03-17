---
title: "AuthZ Api Model"
slug: "AuthZ Api Model"
description: ""
summary: ""
date: 2025-02-14T00:34:10+01:00
lastmod: 2025-02-14T00:34:10+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authz-api-model-c1467e6747d34918b1ca28457537bbc9"
weight: 4002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The **AuthZ Api Model** defines the `payload` of the `Authorization Api` and how it relates to the `Policy-as-Code`.

An `Authorization Api payload` is composed of the `authorization model` and other inputs, such as `subject`, `resource`, and `action`.

## Zone

The `zone` is required to build the AuthZ model.

This is provided as an input to the Authorization Api.

```json
{
  "authorization_model": {
    "zone_id": 268786704340,
  }
}
```

---
**authorization_model/zone_id**: *a unique zone identifier distinguishes each input zone.*

---

## Policy Store

The `policy store` is required to load policies, schemas, and other related data necessary to build the AuthZ model.

This is provided as an input to the Authorization Api.

```json
{
  "authorization_model": {
    "zone_id": 268786704340,
    "policy_store": {
      "kind": "ledger",
      "id": "3b72d00fb7d247848757fb37be8d0814"
    }
  }
}
```

The `Permguard` decision engine loads the policy storage based on the input Type and ID.

---
**authorization_model/policy_store/type**: *the policy store type defines the storage mechanism used for policies (default `LEDGER`, options `LEDGER`).*

---
**authorization_model/policy_store/id**: *the unique identifier of the policy store.*

---

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
    }
  }
}
```

---
**authorization_model/principal/type**: *the principal type (default `USER`, options `USER`).*

---
**authorization_model/principal/id**: *the principal identifier.*

---
**authorization_model/principal/source**: *the principal identity source.*

---

## Entities

The `Entities` object is a `collection of attributes` that represent the entities of a policy.

Each policy language defines its own entity schema.

## Subject

The Subject specifies the entity requesting access to a resource.

- `type`: A required string value that specifies the type of the Subject.
- `id`: A required string value containing the unique identifier of the Subject, scoped to the type.
- `source`: An optional string value that specifies the source of the Subject.
- `properties`: An optional JSON object containing any number of key-value pairs, which can be used to express additional properties of a Subject.

```json
{
  "subject": {
    "type": "user",
    "id": "alice",
    "source": "keycloak",
    "properties": {
      "department": "sales"
    }
  }
}
````

---
**subject/type**: *the subject type (default `USER`, options `USER`).*

---
**subject/id**: *the subject identifier.*

---
**subject/source**: *the subject identity source.*

---
**subject/properties**: *generic properties.*

---

## Resources

The `Resource` specifies the entity requesting access to a resource.

- `type`: A required string value that specifies the type of the Resource.
- `id`: A required string value containing the unique identifier of the Resource, scoped to the type.
- `properties`: An optional JSON object containing any number of key-value pairs, which can be used to express additional properties of a Resource.

```json
{
  "resource":{
    "type": "subscription",
    "id": "e3a786fd07e24bfa95ba4341d3695ae8",
    "properties": {
      "active": true
    }
  }
}
````

---
**resource/type**: *the resource type.*

---
**resource/id**: *the resource identifier.*

---
**resource/properties**: *generic properties.*

---

## Action

The `Action` specifies the entity requesting access to a action.

- `name`: A required string value that specifies the name of the Action.
- `properties`: An optional JSON object containing any number of key-value pairs, which can be used to express additional properties of a Action.

```json
{
  "action":{
    "type": "cancel",
    "properties": {
      "reason": "expired subscription"
    }
  }
}
````

---
**action/type**: *the action type.*

---
**action/properties**: *generic properties.*

---

## Context

The `Context` object is a set of attributes that represent environmental or contextual data about the request such as time of day. It is a JSON [RFC8259](https://www.rfc-editor.org/rfc/rfc8259) object.

```json
{
  "context":{
    "expire_at": "2024-12-26T22:53:00+01:00",
  }
}
````

---
**context**: *generic properties.*

---
