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
    identifier: "azclient-java-sdk-8de22d22284e4e498a54a343b52c6f2a"
weight: 9402
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The application, acting as a Policy Enforcement Point (PEP), enforces policies defined by the Policy Decision Point (PDP). The Permguard Java SDK facilitates communication with the Permguard PDP.

This communication occurs through the `AuthZ Client`, a component that provides a straightforward interface for interacting with the Permguard `AuthZServer`.

## The Basic Structure of an Authorization Request

A standard authorization request is composed of the following key elements:

```java
ObjectMapper objectMapper = new ObjectMapper();
try {
    // Create a new Permguard client
    AZConfig config = new AZConfig("localhost", 9094, true);
    AZClient client = new AZClient(config);

    // Load JSON as InputStream from resources folder
    InputStream inputStream = Check.class.getClassLoader().getResourceAsStream(JSON_FILE_PATH);
    AZRequest request = objectMapper.readValue(inputStream, AZRequest.class);
    AZResponse response = client.check(request);

    if (response == null) {
        System.out.println("❌ Authorization request failed.");
        return;
    }
    if (response.isDecision()) {
        System.out.println("✅ Authorization Permitted");
    } else {
        System.out.println("❌ Authorization Denied");
        if (response.getContext() != null) {
            if (response.getContext().getReasonAdmin() != null) {
                System.out.println("-> Reason Admin: " + response.getContext().getReasonAdmin().getMessage());
            }
            if (response.getContext().getReasonUser() != null) {
                System.out.println("-> Reason User: " + response.getContext().getReasonUser().getMessage());
            }
        }
        if (response.getEvaluations() != null) {
            for (var eval : response.getEvaluations()) {
                if (eval.getContext() != null && eval.getContext().getReasonUser() != null) {
                    System.out.println("-> Evaluation RequestID " + eval.getRequestId()
                            + ": Reason User: " + eval.getContext().getReasonUser().getMessage());
                }
            }
        }
    }
} catch (IOException e) {
    System.err.println("❌ Error loading JSON request: " + e.getMessage());
}
```

## Perform an Atomic Authorization Request

An `atomic authorization` request can be performed using the `AuthZ Client` by creating a new client instance and invoking the `Check` method.

```java
try {
    // Create a new Permguard client
    AZConfig config = new AZConfig("localhost", 9094, true);
    AZClient client = new AZClient(config);

    long zoneId = ZONE_ID;
    String policyStoreId = POLICY_STORE_ID;
    String requestId = "abc1";

    Principal principal = new PrincipalBuilder(EMAIL)
            .withType(USER)
            .withSource(KEYCLOAK)
            .build();

    Entities entities = new Entities("cedar", List.of(
            Map.of(
                    "uid", Map.of("type", "MagicFarmacia::Platform::BranchInfo", "id", "subscription"),
                    "attrs", Map.of("active", true),
                    "parents", List.of()
            )
    ));

    // Build the atomic AZRequest using the exact JSON parameters
    AZRequest request = new AZAtomicRequestBuilder(
            zoneId,
            policyStoreId,
           "platform-creator",  // Subject id from JSON  
            "MagicFarmacia::Platform::Subscription",  // Resource type from JSON
            "MagicFarmacia::Platform::Action::create"  // Action name from JSON
    )
            .withRequestId(requestId)
            .withPrincipal(principal)
            .withEntitiesItems("cedar", entities)
            .withSubjectSource(KEYCLOAK)
            .withSubjectProperty("isSuperUser", true)
            .withResourceId("e3a786fd07e24bfa95ba4341d3695ae8")
            .withResourceProperty("isEnabled", true)
            .withActionProperty("isEnabled", true)
            .withContextProperty("time", "2025-01-23T16:17:46+00:00")
            .withContextProperty("isSubscriptionActive", true)
            .build();

    // Perform atomic authorization check
    AZResponse response = client.check(request);
    if (response == null) {
        System.out.println("❌ Authorization request failed.");
        return;
    }

    if (response.isDecision()) {
        System.out.println("✅ Authorization Permitted");
    } else {
        System.out.println("❌ Authorization Denied");
        if (response.getContext() != null) {
            if (response.getContext().getReasonAdmin() != null) {
                System.out.println("-> Reason Admin: " + response.getContext().getReasonAdmin().getMessage());
            }
            if (response.getContext().getReasonUser() != null) {
                System.out.println("-> Reason User: " + response.getContext().getReasonUser().getMessage());
            }
        }
        if (response.getEvaluations() != null) {
            for (var eval : response.getEvaluations()) {
                if (eval.getContext() != null && eval.getContext().getReasonUser() != null) {
                    System.out.println("-> Evaluation RequestID " + eval.getRequestId()
                            + ": Reason User: " + eval.getContext().getReasonUser().getMessage());
                }
            }
        }
    }
} catch (Exception e) {
    System.err.println("❌ Error executing atomic request: " + e.getMessage());
    e.printStackTrace();
}
```

## Perform a Composed Authorization Request

To perform a composed authorization request using the `AuthZ Client`, you need to create a new client and call the `Check` method.

{{< callout context="note" icon="info-circle" >}}
This type of request is designed for scenarios requiring greater control over the authorization request creation, as well as cases where multiple evaluations must be executed within a single request.
{{< /callout >}}

```java
try {
    // Create a new Permguard client
    AZConfig config = new AZConfig("localhost", 9094, true);
    AZClient client = new AZClient(config);

    // Extract values from JSON (matching your provided data)
    long ZONE_ID = 434033150930L;;
    String POLICY_STORE_ID = "159e2a25fd244f5d96423c53f55100bd";
    String PRINCIPAL_TYPE = "user";
    String PRINCIPAL_ID = "amy.smith@acmecorp.com";
    String PRINCIPAL_SOURCE = "keycloak";
    String SUBJECT_TYPE = "role-actor";
    String SUBJECT_ID = "platform-creator";
    String SUBJECT_SOURCE = "keycloak";
    String REQUEST_ID = "abc1";
    String RESOURCE_TYPE = "MagicFarmacia::Platform::Subscription";
    String RESOURCE_ID = "e3a786fd07e24bfa95ba4341d3695ae8";
    String ACTION_CREATE = "MagicFarmacia::Platform::Action::create";
    String ACTION_VIEW = "MagicFarmacia::Platform::Action::view";

    // Create Principal
    Principal principal = new PrincipalBuilder(PRINCIPAL_ID)
            .withType(PRINCIPAL_TYPE)
            .withSource(PRINCIPAL_SOURCE)
            .build();

    // Create Subject
    Subject subject = new SubjectBuilder(SUBJECT_ID)
            .withType(SUBJECT_TYPE)
            .withSource(SUBJECT_SOURCE)
            .withProperty("isSuperUser", true)
            .build();

    // Create Resource
    Resource resource = new ResourceBuilder(RESOURCE_TYPE)
            .withId(RESOURCE_ID)
            .withProperty("isEnabled", true)
            .build();

    // Create Actions
    Action actionViewEnabled = new ActionBuilder(ACTION_VIEW) //Not Permitted!
            .withProperty("isEnabled", true)
            .build();

    Action actionViewDisabled = new ActionBuilder(ACTION_VIEW) //Not Permitted!
            .withProperty("isEnabled", false)
            .build();

    Action actionCreateEnabled = new ActionBuilder(ACTION_CREATE) //Permitted!
            .withProperty("isEnabled", true)
            .build();

    Action actionCreateDisabled = new ActionBuilder(ACTION_CREATE) //Not Permitted!
            .withProperty("isEnabled", false)
            .build();

    // Create Context
    Map<String, Object> context = Map.of(
            "time", "2025-01-23T16:17:46+00:00",
            "isSubscriptionActive", true
    );

    // Create Evaluations
    Evaluation evaluationOne = new EvaluationBuilder(subject, resource, actionCreateEnabled)
            .withRequestId("exz1")
            .withContext(context)
            .build();

    Evaluation evaluationTwo = new EvaluationBuilder(subject, resource, actionCreateEnabled)
            .withRequestId("exz2")
            .withContext(context)
            .build();

    // Create Entities
    Entities entities = new Entities("cedar", List.of(
            Map.of(
                    "uid", Map.of("type", "MagicFarmacia::Platform::BranchInfo", "id", "subscription"),
                    "attrs", Map.of("active", true),
                    "parents", List.of()
            )
    ));

    // Build the AZRequest with multiple evaluations
    AZRequest request = new AZRequestBuilder(ZONE_ID, POLICY_STORE_ID)
            .withRequestId(REQUEST_ID)
            .withPrincipal(principal)
            .withEntitiesItems(entities.getSchema(), entities)
            .withEvaluation(evaluationOne)
            .withEvaluation(evaluationTwo)
            .build();

    // Perform authorization check with multiple evaluations
    AZResponse response = client.check(request);
    if (response == null) {
        System.out.println("❌ Authorization request failed.");
        return;
    }

    if (response.isDecision()) {
        System.out.println("✅ Authorization Permitted");
    } else {
        System.out.println("❌ Authorization Denied");
        if (response.getContext() != null) {
            if (response.getContext().getReasonAdmin() != null) {
                System.out.println("-> Reason Admin: " + response.getContext().getReasonAdmin().getMessage());
            }
            if (response.getContext().getReasonUser() != null) {
                System.out.println("-> Reason User: " + response.getContext().getReasonUser().getMessage());
            }
        }
        if (response.getEvaluations() != null) {
            for (var eval : response.getEvaluations()) {
                if (eval.getContext() != null && eval.getContext().getReasonUser() != null) {
                    System.out.println("-> Evaluation RequestID " + eval.getRequestId()
                            + ": Reason User: " + eval.getContext().getReasonUser().getMessage());
                }
            }
        }
    }
} catch (Exception e) {
    System.err.println("❌ Error executing multiple evaluations request: " + e.getMessage());
    e.printStackTrace();
}
```
