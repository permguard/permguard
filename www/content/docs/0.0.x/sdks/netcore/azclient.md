---
title: "AuthZClient"
slug: "AuthZClient"
description: ""
summary: ""
date: 2024-02-18T17:14:43+01:00
lastmod: 2024-02-18T17:14:43+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "azclient-netcore-sdk-c387de5476bf41889fb7dbc70c7bc6a7"
weight: 9602
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The application, acting as a Policy Enforcement Point (PEP), enforces policies defined by the Policy Decision Point (PDP). The Permguard .NET Core SDK facilitates communication with the Permguard PDP.

This communication occurs through the `AuthZClient`, a component that provides a straightforward interface for interacting with the Permguard `AuthZServer`.

## The Basic Structure of an Authorization Request

A standard authorization request is composed of the following key elements:

```csharp
try
{
    // Create a new Permguard client
    var client = new AzClient(new AzConfig().WithEndpoint(new AzEndpoint("http", 9094, "localhost")));

    // Load the json file
    var filePath = Path.Combine(AppContext.BaseDirectory, "../../../ok_onlyone1.json");
    if (!File.Exists(filePath))
    {
        Console.WriteLine("❌ Failed to load the json file");
        throw new Exception("Failed to load the json file");
    }
    var jsonContent = File.ReadAllText(filePath);
    var request = JsonSerializer.Deserialize<AzRequest>(jsonContent);

    // Check the authorization
    var response = client.CheckAuth(request);
    if (response == null)
    {
        Console.WriteLine("❌ Failed to check auth.");
        throw new Exception("Failed to check auth response");
    }
    if (response.Decision) {
        Console.WriteLine("✅ Authorization Permitted");
    }
    else
    {
        Console.WriteLine("❌ Authorization Denied");
        if (response.Context != null) {
            if (response.Context?.ReasonAdmin != null)
            {
                Console.WriteLine($"-> Reason Admin: {response.Context?.ReasonAdmin?.Message}");
            }
            if (response.Context?.ReasonUser != null)
            {
                Console.WriteLine($"-> Reason User: {response.Context?.ReasonUser?.Message}");
            }
        }
        foreach (var eval in response.Evaluations)
        {
            if (eval.Decision)
            {
                Console.WriteLine("-> ✅ Authorization Permitted");
            }
            if (eval.Context != null) {
                if (eval.Context?.ReasonAdmin != null)
                {
                    Console.WriteLine($"-> Reason Admin: {eval.Context?.ReasonAdmin?.Message}");
                }
                if (eval.Context?.ReasonUser != null)
                {
                    Console.WriteLine($"-> Reason User: {eval.Context?.ReasonUser?.Message}");
                }
            }
        }
    }
}
catch (Exception e)
{
    Console.WriteLine("❌ Failed to check auth.");
    throw;
}
```

## Perform an Atomic Authorization Request

An `atomic authorization` request can be performed using the `AuthZClient` by creating a new client instance and invoking the `Check` method.

```csharp
try
{
    // Create a new Permguard client
    var client = new AzClient(new AzConfig().WithEndpoint(new AzEndpoint("http", 9094, "localhost")));

    // Create the Principal
    var principal = new PrincipalBuilder("amy.smith@acmecorp.com")
        .WithSource("keycloak")
        .WithKind("user")
        .Build();

    // Create the entities
    var entities = new List<Dictionary<string, object>?>
    {
        new()
        {
            { "uid", new Dictionary<string,object>
                {
                    { "type", "MagicFarmacia::Platform::BranchInfo" },
                    { "id", "subscription" }
                }
            },
            { "attrs", new Dictionary<string, object> { { "active", true } } },
            { "parents", new List<object>() }
        }
    };

    // Create a new authorization request
    var request = new AzAtomicRequestBuilder(285374414806,
            "f81aec177f8a44a48b7ceee45e05507f",
            "platform-creator",
            "MagicFarmacia::Platform::Subscription",
            "MagicFarmacia::Platform::Action::create")
        // RequestID
        .WithRequestId("31243")
        // Principal
        .WithPrincipal(principal)
        // Entities
        .WithEntitiesMap("cedar", entities)
        // Subject
        .WithSubjectKind("role-actor")
        .WithSubjectSource("keycloak")
        .WithSubjectProperty("isSuperUser", true)
        // Resource
        .WithResourceId("e3a786fd07e24bfa95ba4341d3695ae8")
        .WithResourceProperty("isEnabled", true)
        // Action
        .WithActionProperty("isEnabled", true)
        // Context
        .WithContextProperty("isSubscriptionActive", true)
        .WithContextProperty("time", "2025-01-23T16:17:46+00:00")
        .Build();

    // Check the authorization
    var response = client.CheckAuth(request);
    if (response == null)
    {
        Console.WriteLine("❌ Failed to check auth.");
        throw new Exception("Failed to check auth response");
    }
    if (response.Decision) {
        Console.WriteLine("✅ Authorization Permitted");
    }
    else
    {
        Console.WriteLine("❌ Authorization Denied");
        if (response.Context != null) {
            if (response.Context?.ReasonAdmin != null)
            {
                Console.WriteLine($"-> Reason Admin: {response.Context?.ReasonAdmin?.Message}");
            }
            if (response.Context?.ReasonUser != null)
            {
                Console.WriteLine($"-> Reason User: {response.Context?.ReasonUser?.Message}");
            }
        }
        foreach (var eval in response.Evaluations)
        {
            if (eval.Decision)
            {
                Console.WriteLine("-> ✅ Authorization Permitted");
            }
            if (eval.Context != null) {
                if (eval.Context?.ReasonAdmin != null)
                {
                    Console.WriteLine($"-> Reason Admin: {eval.Context?.ReasonAdmin?.Message}");
                }
                if (eval.Context?.ReasonUser != null)
                {
                    Console.WriteLine($"-> Reason User: {eval.Context?.ReasonUser?.Message}");
                }
            }
        }
    }
}
catch (Exception e)
{
    Console.WriteLine("❌ Failed to check auth.");
    throw;
}
```

## Perform a Composed Authorization Request

To perform a composed authorization request using the `AuthZClient`, you need to create a new client and call the `Check` method.

{{< callout context="note" icon="info-circle" >}}
This type of request is designed for scenarios requiring greater control over the authorization request creation, as well as cases where multiple evaluations must be executed within a single request.
{{< /callout >}}

```csharp
try
{
    // Create a new Permguard client
    var client = new AzClient(new AzConfig().WithEndpoint(new AzEndpoint("http", 9094, "localhost")));

    // Create the Principal
    var principal = new PrincipalBuilder("amy.smith@acmecorp.com")
        .WithSource("keycloak")
        .WithKind("user").Build();

    // Create a new subject
    var subject = new SubjectBuilder("platform-creator")
        .WithSource("keycloak")
        .WithKind("role-actor")
        .WithProperty("isSuperUser", true)
        .Build();

    // Create a new resource
    var resource = new ResourceBuilder("MagicFarmacia::Platform::Subscription")
        .WithId("e3a786fd07e24bfa95ba4341d3695ae8")
        .WithProperty("isEnabled", true)
        .Build();

    // Create ations
    var actionView = new ActionBuilder("MagicFarmacia::Platform::Action::create")
        .WithProperty("isEnabled", true)
        .Build();

    var actionCreate = new ActionBuilder("MagicFarmacia::Platform::Action::create")
        .WithProperty("isEnabled", false)
        .Build();

    // Create a new Context
    var context = new ContextBuilder()
        .WithProperty("time", "2025-01-23T16:17:46+00:00")
        .WithProperty("isSubscriptionActive", true)
        .Build();

    // Create evaluations
    var evaluationView = new EvaluationBuilder(subject, resource, actionView)
        .WithRequestId("134")
        .Build();

    var evaluationCreate = new EvaluationBuilder(subject, resource, actionCreate)
        .WithRequestId("435")
        .Build();

    // Create the entities
    var entities = new List<Dictionary<string, object>?>
    {
        new()
        {
            { "uid", new Dictionary<string,object>
                {
                    { "type", "MagicFarmacia::Platform::BranchInfo" },
                    { "id", "subscription" }
                }
            },
            { "attrs", new Dictionary<string, object> { { "active", true } } },
            { "parents", new List<object>() }
        }
    };

    // Create a new authorization request
    var request = new AzRequestBuilder(285374414806, "f81aec177f8a44a48b7ceee45e05507f")
        .WithRequestId("123457")
        .WithSubject(subject)
        .WithPrincipal(principal)
        .WithEntitiesMap("cedar", entities)
        .WithContext(context)
        .WithEvaluation(evaluationView)
        .WithEvaluation(evaluationCreate)
        .Build();

    // Check the authorization
    var response = client.CheckAuth(request);
    if (response == null)
    {
        Console.WriteLine("❌ Failed to check auth.");
        throw new Exception("Failed to check auth response");
    }
    if (response.Decision) {
        Console.WriteLine("✅ Authorization Permitted");
    }
    else
    {
        Console.WriteLine("❌ Authorization Denied");
        if (response.Context != null) {
            if (response.Context?.ReasonAdmin != null)
            {
                Console.WriteLine($"-> Reason Admin: {response.Context?.ReasonAdmin?.Message}");
            }
            if (response.Context?.ReasonUser != null)
            {
                Console.WriteLine($"-> Reason User: {response.Context?.ReasonUser?.Message}");
            }
        }
        foreach (var eval in response.Evaluations)
        {
            if (eval.Decision)
            {
                Console.WriteLine("-> ✅ Authorization Permitted");
            }
            if (eval.Context != null) {
                if (eval.Context?.ReasonAdmin != null)
                {
                    Console.WriteLine($"-> Reason Admin: {eval.Context?.ReasonAdmin?.Message}");
                }
                if (eval.Context?.ReasonUser != null)
                {
                    Console.WriteLine($"-> Reason User: {eval.Context?.ReasonUser?.Message}");
                }
            }
        }
    }
}
catch (Exception e)
{
    Console.WriteLine("❌ Failed to check auth.");
    throw;
}
```
