---
title: "AuthZ Client"
slug: "AuthZ Client"
description: ""
summary: ""
date: 2024-02-18T17:14:43+01:00
lastmod: 2024-02-18T17:14:43+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "azclient-node-sdk-2a72f8f042c44629922bba97b259776f"
weight: 9302
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The application, acting as a Policy Enforcement Point (PEP), enforces policies defined by the Policy Decision Point (PDP). The Permguard Node SDK facilitates communication with the Permguard PDP.

This communication occurs through the `AuthZ Client`, a component that provides a straightforward interface for interacting with the Permguard `AuthZServer`.

## The Basic Structure of an Authorization Request

A standard authorization request is composed of the following key elements:

```typescript
import { withEndpoint, AZClient } from "@permguard/permguard";

// Create a new Permguard client
const azClient = new AZClient(withEndpoint("localhost", 9094));

// Check the authorization
const { decision, response } = await azClient.check(json_ok_onlyone);
if (decision) {
  console.log("✅ Authorization Permitted");
} else {
  console.log("❌ Authorization Denied");
  if (response) {
    if (response.Context?.ReasonAdmin) {
      console.log(`-> Reason Admin: ${response.Context.ReasonAdmin.Message}`);
    }
    if (response.Context?.ReasonUser) {
      console.log(`-> Reason User: ${response.Context.ReasonUser.Message}`);
    }
    for (const evaluation of response.Evaluations || []) {
      if (evaluation.Context?.ReasonAdmin) {
        console.log(
          `-> Reason Admin: ${evaluation.Context.ReasonAdmin.Message}`
        );
      }
      if (evaluation.Context?.ReasonUser) {
        console.log(`-> Reason User: ${evaluation.Context.ReasonUser.Message}`);
      }
    }
  }
}
```

## Perform an Atomic Authorization Request

An `atomic authorization` request can be performed using the `AuthZ Client` by creating a new client instance and invoking the `Check` method.

```typescript
import {
  PrincipalBuilder,
  AZAtomicRequestBuilder,
  withEndpoint,
  AZClient,
} from "@permguard/permguard";

// Create a new Permguard client
const azClient = new AZClient(withEndpoint("localhost", 9094));

// Create the Principal
const principal = new PrincipalBuilder("amy.smith@acmecorp.com").build();

// Create the entities
const entities = [
  {
    uid: {
      type: "MagicFarmacia::Platform::BranchInfo",
      id: "subscription",
    },
    attrs: {
      active: true,
    },
    parents: [],
  },
];

// Create a new authorization request
const req = new AZAtomicRequestBuilder(
  633687665465,
  "fc260e783b0c4bd6aa88eed18f57aab3",
  "platform-creator",
  "MagicFarmacia::Platform::Subscription",
  "MagicFarmacia::Platform::Action::create"
)
  .withRequestID("1234")
  .withPrincipal(principal)
  .withEntitiesItems("cedar", entities)
  .withSubjectRoleActorType()
  .withSubjectSource("keycloack")
  .withSubjectProperty("isSuperUser", true)
  .withResourceID("e3a786fd07e24bfa95ba4341d3695ae8")
  .withResourceProperty("isEnabled", true)
  .withActionProperty("isEnabled", true)
  .withContextProperty("time", "2025-01-23T16:17:46+00:00")
  .withContextProperty("isSubscriptionActive", true)
  .build();

// Check the authorization
const { decision, response } = await azClient.check(req);
if (decision) {
  console.log("✅ Authorization Permitted");
} else {
  console.log("❌ Authorization Denied");
  if (response) {
    if (response.Context?.ReasonAdmin) {
      console.log(`-> Reason Admin: ${response.Context.ReasonAdmin.Message}`);
    }
    if (response.Context?.ReasonUser) {
      console.log(`-> Reason User: ${response.Context.ReasonUser.Message}`);
    }
    for (const evaluation of response.Evaluations || []) {
      if (evaluation.Context?.ReasonAdmin) {
        console.log(
          `-> Reason Admin: ${evaluation.Context.ReasonAdmin.Message}`
        );
      }
      if (evaluation.Context?.ReasonUser) {
        console.log(`-> Reason User: ${evaluation.Context.ReasonUser.Message}`);
      }
    }
  }
}
```

## Perform a Composed Authorization Request

To perform a composed authorization request using the `AuthZ Client`, you need to create a new client and call the `Check` method.

{{< callout context="note" icon="info-circle" >}}
This type of request is designed for scenarios requiring greater control over the authorization request creation, as well as cases where multiple evaluations must be executed within a single request.
{{< /callout >}}

```typescript
import {
  PrincipalBuilder,
  withEndpoint,
  AZClient,
  SubjectBuilder,
  ResourceBuilder,
  ActionBuilder,
  ContextBuilder,
  EvaluationBuilder,
  AZRequestBuilder,
} from "@permguard/permguard";

// Create a new Permguard client
const azClient = new AZClient(withEndpoint("localhost", 9094));

// Create a new subject
const subject = new SubjectBuilder("platform-creator")
  .withRoleActorType()
  .withSource("keycloack")
  .withProperty("isSuperUser", true)
  .build();

// Create a new resource
const resource = new ResourceBuilder("MagicFarmacia::Platform::Subscription")
  .withID("e3a786fd07e24bfa95ba4341d3695ae8")
  .withProperty("isEnabled", true)
  .build();

// Create actions
const actionView = new ActionBuilder("MagicFarmacia::Platform::Action::create")
  .withProperty("isEnabled", true)
  .build();

const actionCreate = new ActionBuilder(
  "MagicFarmacia::Platform::Action::create"
)
  .withProperty("isEnabled", true)
  .build();

// Create a new Context
const context = new ContextBuilder()
  .withProperty("time", "2025-01-23T16:17:46+00:00")
  .withProperty("isSubscriptionActive", true)
  .build();

// Create evaluations
const evaluationView = new EvaluationBuilder(subject, resource, actionView)
  .withRequestID("1234")
  .withContext(context)
  .build();

const evaluationCreate = new EvaluationBuilder(subject, resource, actionCreate)
  .withRequestID("7890")
  .withContext(context)
  .build();

// Create the Principal
const principal = new PrincipalBuilder("amy.smith@acmecorp.com").build();

// Create the entities
const entities = [
  {
    uid: {
      type: "MagicFarmacia::Platform::BranchInfo",
      id: "subscription",
    },
    attrs: {
      active: true,
    },
    parents: [],
  },
];

// Create a new authorization request
const req = new AZRequestBuilder(
  633687665465,
  "fc260e783b0c4bd6aa88eed18f57aab3"
)
  .withPrincipal(principal)
  .withEntitiesItems("cedar", entities)
  .withEvaluation(evaluationView)
  .withEvaluation(evaluationCreate)
  .build();

// Check the authorization
const { decision, response } = await azClient.check(req);
if (decision) {
  console.log("✅ Authorization Permitted");
} else {
  console.log("❌ Authorization Denied");
  if (response) {
    if (response.Context?.ReasonAdmin) {
      console.log(`-> Reason Admin: ${response.Context.ReasonAdmin.Message}`);
    }
    if (response.Context?.ReasonUser) {
      console.log(`-> Reason User: ${response.Context.ReasonUser.Message}`);
    }
    for (const evaluation of response.Evaluations || []) {
      if (evaluation.Context?.ReasonAdmin) {
        console.log(
          `-> Reason Admin: ${evaluation.Context.ReasonAdmin.Message}`
        );
      }
      if (evaluation.Context?.ReasonUser) {
        console.log(`-> Reason User: ${evaluation.Context.ReasonUser.Message}`);
      }
    }
  }
}
```
