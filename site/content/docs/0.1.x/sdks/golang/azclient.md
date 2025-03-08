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
    identifier: "azclient-go-sdk-2b0edf41babb4bf8abfc0897faa6ce3e"
weight: 9102
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The application, acting as a Policy Enforcement Point (PEP), enforces policies defined by the Policy Decision Point (PDP). The Permguard Go SDK facilitates communication with the Permguard PDP.

This communication occurs through the `AuthZ Client`, a component that provides a straightforward interface for interacting with the Permguard `AuthZ Server`.

## The Basic Structure of an Authorization Request

A standard authorization request is composed of the following key elements:

```go
// Create a new Permguard client
azClient := permguard.NewAZClient(
  permguard.WithEndpoint("localhost", 9094),
)

// Create a new authorization request
req := azreq.NewAZAtomicRequestBuilder(273165098782, "fd1ac44e4afa4fc4beec622494d3175a",
  "amy.smith@acmecorp.com", "MagicFarmacia::Platform::Subscription", "MagicFarmacia::Platform::Action::create")

// Check the authorization
decsion, _, _ := azClient.Check(req)
if decsion {
  fmt.Println("✅ Authorization Permitted")
} else {
  fmt.Println("❌ Authorization Denied")
}
```

## Perform an Atomic Authorization Request

An `atomic authorization` request can be performed using the `AuthZ Client` by creating a new client instance and invoking the `Check` method.

```go
// Create a new Permguard client
azClient := permguard.NewAZClient(
  permguard.WithEndpoint("localhost", 9094),
)

// Create the Principal
principal := azreq.NewPrincipalBuilder("amy.smith@acmecorp.com").Build()

// Create the entities
entities := []map[string]any{
  {
      "uid": map[string]any{
      "type": "MagicFarmacia::Platform::BranchInfo",
      "id":   "subscription",
      },
      "attrs": map[string]any{
      "active": true,
    },
    "parents": []any{},
  },
}

// Create a new authorization request
req := azreq.NewAZAtomicRequestBuilder(273165098782, "fd1ac44e4afa4fc4beec622494d3175a",
  "amy.smith@acmecorp.com", "MagicFarmacia::Platform::Subscription", "MagicFarmacia::Platform::Action::create").
  // RequestID
  WithRequestID("1234").
  // Principal
  WithPrincipal(principal).
  // Entities
  WithEntitiesItems(azreq.CedarEntityKind, entities).
  // Subject
  WithSubjectKind(azreq.UserType).
  WithSubjectSource("keycloack").
  WithSubjectProperty("isSuperUser", true).
  // Resource
  WithResourceID("e3a786fd07e24bfa95ba4341d3695ae8").
  WithResourceProperty("isEnabled", true).
  // Action
  WithActionProperty("isEnabled", true).
  WithContextProperty("time", "2025-01-23T16:17:46+00:00").
  WithContextProperty("isSubscriptionActive", true).
  Build()

// Check the authorization
decsion, response, _ := azClient.Check(req)
if decsion {
  fmt.Println("✅ Authorization Permitted")
} else {
  fmt.Println("❌ Authorization Denied")
  if response.Context.ReasonAdmin != nil {
    fmt.Printf("-> Reason Admin: %s\n", response.Context.ReasonAdmin.Message)
  }
  if response.Context.ReasonUser != nil {
    fmt.Printf("-> Reason User: %s\n", response.Context.ReasonUser.Message)
  }
  for _, eval := range response.Evaluations {
    if eval.Context.ReasonUser != nil {
      fmt.Printf("-> Reason Admin: %s\n", eval.Context.ReasonAdmin.Message)
      fmt.Printf("-> Reason User: %s\n", eval.Context.ReasonUser.Message)
    }
  }
}
```

## Perform a Composed Authorization Request

To perform a composed authorization request using the `AuthZ Client`, you need to create a new client and call the `Check` method.

{{< callout context="note" icon="info-circle" >}}
This type of request is designed for scenarios requiring greater control over the authorization request creation, as well as cases where multiple evaluations must be executed within a single request.
{{< /callout >}}

```go
// Create a new Permguard client
azClient := permguard.NewAZClient(
  permguard.WithEndpoint("localhost", 9094),
)

// Create a new subject
subject := azreq.NewSubjectBuilder("amy.smith@acmecorp.com").
  WithKind(azreq.UserType).
  WithSource("keycloack").
  WithProperty("isSuperUser", true).
  Build()

// Create a new resource
resource := azreq.NewResourceBuilder("MagicFarmacia::Platform::Subscription").
  WithID("e3a786fd07e24bfa95ba4341d3695ae8").
  WithProperty("isEnabled", true).
  Build()

// Create ations
actionView := azreq.NewActionBuilder("MagicFarmacia::Platform::Action::create").
  WithProperty("isEnabled", true).
  Build()

actionCreate := azreq.NewActionBuilder("MagicFarmacia::Platform::Action::create").
  WithProperty("isEnabled", true).
  Build()

// Create a new Context
context := azreq.NewContextBuilder().
  WithProperty("time", "2025-01-23T16:17:46+00:00").
  WithProperty("isSubscriptionActive", true).
  Build()

// Create evaluations
evaluationView := azreq.NewEvaluationBuilder(subject, resource, actionView).
  WithRequestID("1234").
  WithContext(context).
  Build()

evaluationCreate := azreq.NewEvaluationBuilder(subject, resource, actionCreate).
  WithRequestID("7890").
  WithContext(context).
  Build()

// Create the Principal
principal := azreq.NewPrincipalBuilder("amy.smith@acmecorp.com").Build()

// Create the entities
entities := []map[string]any{
  {
    "uid": map[string]any{
      "type": "MagicFarmacia::Platform::BranchInfo",
      "id":   "subscription",
    },
    "attrs": map[string]any{
    "active": true,
    },
    "parents": []any{},
  },
}

// Create a new authorization request
req := azreq.NewAZRequestBuilder(273165098782, "fd1ac44e4afa4fc4beec622494d3175a").
  WithPrincipal(principal).
  WithEntitiesItems(azreq.CedarEntityKind, entities).
  WithEvaluation(evaluationView).
  WithEvaluation(evaluationCreate).
  Build()

// Check the authorization
decsion, response, _ := azClient.Check(req)
if decsion {
  fmt.Println("✅ Authorization Permitted")
} else {
  fmt.Println("❌ Authorization Denied")
  if response.Context.ReasonAdmin != nil {
    fmt.Printf("-> Reason Admin: %s\n", response.Context.ReasonAdmin.Message)
  }
  if response.Context.ReasonUser != nil {
    fmt.Printf("-> Reason User: %s\n", response.Context.ReasonUser.Message)
  }
  for _, eval := range response.Evaluations {
    if eval.Context.ReasonUser != nil {
      fmt.Printf("-> Reason Admin: %s\n", eval.Context.ReasonAdmin.Message)
      fmt.Printf("-> Reason User: %s\n", eval.Context.ReasonUser.Message)
    }
  }
}
```
