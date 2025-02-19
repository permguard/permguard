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
    identifier: "azclient-go-sdk-8f45facec1914c68aa38ba456f98ae5c"
weight: 9102
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The application, acting as a Policy Enforcement Point (PEP), enforces policies defined by the Policy Decision Point (PDP). It can use the PermGuard Go SDK to communicate with the PermGuard PDP.

This communication happens through the AuthZ Client, a library that provides a straightforward interface to interact with the PermGuard AuthZ Server.

## Perform an Atomic Authorization Request

To perform an atomic authorization request using the AZ Client, you need to create a new client and call the `Check` method.

```go
// Create a new Permguard client
azClient := permguard.NewAZClient(
  permguard.WithPDPEndpoint("localhost", 9094),
)

principal := permguard.NewPrincipalBuilder("amy.smith@acmecorp.com").Build()

req := permguard.NewAZAtomicRequestBuilder(273165098782, "fd1ac44e4afa4fc4beec622494d3175a",
  "amy.smith@acmecorp.com", "MagicFarmacia::Platform::Subscription", "MagicFarmacia::Platform::Action::view").
  // RequestID
  WithRequestID("1234").
  // Principal
  WithPrincipal(principal).
  // Subject
  WithSubjectKind("user").
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
decsion := azClient.Check(req)
if decsion {
  fmt.Println("✅ Authorization Permitted")
} else {
  fmt.Println("❌ Authorization Denied")
}
```

## Perform a Composed Authorization Request

To perform a composed authorization request using the AZ Client, you need to create a new client and call the `Check` method.

```go
// Create a new Permguard client
azClient := permguard.NewAZClient(
  permguard.WithPDPEndpoint("localhost", 9094),
)

principal := permguard.NewPrincipalBuilder("amy.smith@acmecorp.com").Build()

// Create a new subject
subject := permguard.NewSubjectBuilder("amy.smith@acmecorp.com").
  WithKind("user").
  WithSource("keycloack").
  WithProperty("isSuperUser", true).
  Build()

// Create a new resource
resource := permguard.NewResourceBuilder("MagicFarmacia::Platform::Subscription").
  WithID("e3a786fd07e24bfa95ba4341d3695ae8").
  WithProperty("isEnabled", true).
  Build()

// Create ations
actionView := permguard.NewActionBuilder("MagicFarmacia::Platform::Action::view").
  WithProperty("isEnabled", true).
  Build()

actionCreate := permguard.NewActionBuilder("MagicFarmacia::Platform::Action::create").
  WithProperty("isEnabled", true).
  Build()

// Create a new Context
context := permguard.NewContextBuilder().
  WithProperty("time", "2025-01-23T16:17:46+00:00").
  WithProperty("isSubscriptionActive", true).
  Build()

// Create evaluations
evaluationView := permguard.NewAZEvaluationBuilder(subject, resource, actionView).
  WithRequestID("1234").
  WithPrincipal(principal).
  WithContext(context).
  Build()

evaluationCreate := permguard.NewAZEvaluationBuilder(subject, resource, actionCreate).
  WithRequestID("7890").
  WithPrincipal(principal).
  WithContext(context).
  Build()

// Create a new request
req := permguard.NewAZRequestBuilder(273165098782, "fd1ac44e4afa4fc4beec622494d3175a").
  WithEvaluation(evaluationView).
  WithEvaluation(evaluationCreate).
  Build()

// Check the authorization
decsion := azClient.Check(req)
if decsion {
  fmt.Println("✅ Authorization Permitted")
} else {
  fmt.Println("❌ Authorization Denied")
}
```
