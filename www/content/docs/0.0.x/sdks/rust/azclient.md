---
title: "AuthZClient"
slug: "AuthZClient"
description: ""
summary: ""
date: 2025-02-18T17:14:43+01:00
lastmod: 2025-02-18T17:14:43+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "azclient-rust-sdk-2b0edf41babb4bf8abfc0897faa6ce3e"
weight: 9202
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The application, acting as a Policy Enforcement Point (PEP), enforces policies defined by the Policy Decision Point (PDP). The Permguard Go SDK facilitates communication with the Permguard PDP.

This communication occurs through the `AuthZClient`, a component that provides a straightforward interface for interacting with the Permguard `AuthZServer`.

## The Basic Structure of an Authorization Request

A standard authorization request is composed of the following key elements:

```rust
    let endpoint = AzEndpoint::new("http", 9094, "localhost");
    let config = AzConfig::new().with_endpoint(Some(endpoint));
    let client = AzClient::new(config);

    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("./json/ok_onlyone.json");

    if !file_path.exists() {
        eprintln!("❌ Failed to load the JSON file");
        return Err(Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Failed to load the JSON file",
        ))));
    }

    let json_content = fs::read_to_string(&file_path).await;
    let request: AzRequest = match serde_json::from_str(&json_content.unwrap()) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("❌ Failed to parse JSON: {}", e);
            return Err(Err(Box::new(e) as Box<dyn std::error::Error>));
        }
    };

    match client.check_auth(Some(request)).await {
        Ok(response) => {
            if response.decision {
                println!("✅ Authorization Permitted");
            } else {
                println!("❌ Authorization Denied");
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to check auth: {}", e);
            return Err(Err(e.into()));
        }
    }
```

## Perform an Atomic Authorization Request

An `atomic authorization` request can be performed using the `AuthZClient` by creating a new client instance and invoking the `Check` method.

```rust
    let endpoint = AzEndpoint::new("http", 9094, "localhost");
    let config = AzConfig::new().with_endpoint(Some(endpoint));
    let client = AzClient::new(config);

    let principal = PrincipalBuilder::new("amy.smith@acmecorp.com")
        .with_source("keycloak")
        .with_type("user")
        .build();

    let entity = {
        let mut map = HashMap::new();
        map.insert("uid".to_string(), json!({
            "type": "MagicFarmacia::Platform::BranchInfo",
            "id": "subscription"
        }));
        map.insert("attrs".to_string(), json!({"active": true}));
        map.insert("parents".to_string(), json!([]));
        Some(map)
    };

    let entities = vec![entity];

    let request = AzAtomicRequestBuilder::new(
        189106194833,
        "48335ae72b3b405eae9e4bd5b07732df",
        "platform-creator",
        "MagicFarmacia::Platform::Subscription",
        "MagicFarmacia::Platform::Action::create",
    )
        .with_request_id("31243")
        .with_principal(principal)
        .with_subject_property("isSuperUser", Value::from(true))
        .with_subject_type("workload")
        .with_subject_source("keycloak")
        .with_resource_id("e3a786fd07e24bfa95ba4341d3695ae8")
        .with_resource_property("isEnabled", json!(true))
        .with_entities_map("cedar", entities)
        .with_action_property("isEnabled", json!(true))
        .with_context_property("isSubscriptionActive", json!(true))
        .with_context_property("time", json!("2025-01-23T16:17:46+00:00"))
        .build();

    match client.check_auth(Some(request)).await {
        Ok(response) => {
            if response.decision {
                println!("✅ Authorization Permitted");
            } else {
                println!("❌ Authorization Denied");
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to check auth: {}", e);
            return Err(Err(e.into()));
        }
    }
```

## Perform a Composed Authorization Request

To perform a composed authorization request using the `AuthZClient`, you need to create a new client and call the `Check` method.

{{< callout context="note" icon="info-circle" >}}
This type of request is designed for scenarios requiring greater control over the authorization request creation, as well as cases where multiple evaluations must be executed within a single request.
{{< /callout >}}

```rust
    let endpoint = AzEndpoint::new("http", 9094, "localhost");
    let config = AzConfig::new().with_endpoint(Some(endpoint));
    let client = AzClient::new(config);

    // Create the Principal
    let principal = PrincipalBuilder::new("amy.smith@acmecorp.com")
        .with_source("keycloak")
        .with_type("user")
        .build();

    // Create a new subject
    let subject = SubjectBuilder::new("platform-creator")
        .with_source("keycloak")
        .with_type("workload")
        .with_property("isSuperUser", serde_json::json!(true))
        .build();

    // Create a new resource
    let resource = ResourceBuilder::new("MagicFarmacia::Platform::Subscription")
        .with_id("e3a786fd07e24bfa95ba4341d3695ae8")
        .with_property("isEnabled", serde_json::json!(true))
        .build();

    // Create actions
    let action_view = ActionBuilder::new("MagicFarmacia::Platform::Action::create")
        .with_property("isEnabled", serde_json::json!(true))
        .build();

    let action_create = ActionBuilder::new("MagicFarmacia::Platform::Action::create")
        .with_property("isEnabled", serde_json::json!(false))
        .build();

    // Create a new Context
    let context = ContextBuilder::new()
        .with_property("time", serde_json::json!("2025-01-23T16:17:46+00:00"))
        .with_property("isSubscriptionActive", serde_json::json!(true))
        .build();

    // Create evaluations
    let evaluation_view = EvaluationBuilder::new(Some(subject.clone()), Some(resource.clone()), Some(action_view.clone()))
        .with_request_id("134")
        .build();

    let evaluation_create = EvaluationBuilder::new(Some(subject.clone()), Some(resource.clone()), Some(action_create.clone()))
        .with_request_id("435")
        .build();

    // Create the entities
    let mut entity = HashMap::new();
    entity.insert(
        "uid".to_string(),
        serde_json::json!({
            "type": "MagicFarmacia::Platform::BranchInfo",
            "id": "subscription"
        }),
    );
    entity.insert(
        "attrs".to_string(),
        serde_json::json!({
            "active": true
        }),
    );
    entity.insert("parents".to_string(), serde_json::json!([]));

    let entities = vec![Some(entity)];

    // Create a new authorization request
    let request = AzRequestBuilder::new(189106194833, "48335ae72b3b405eae9e4bd5b07732df")
        .with_request_id(Some("7567".to_string()))
        .with_subject(Some(subject))
        .with_principal(Some(principal))
        .with_entities_map("cedar", entities)
        .with_context(Some(context))
        .with_evaluation(evaluation_view)
        .with_evaluation(evaluation_create)
        .build();

    match client.check_auth(Some(request)).await {
        Ok(response) => {
            if response.decision {
                println!("✅ Authorization Permitted");
            } else {
                println!("❌ Authorization Denied");
                if let Some(ctx) = response.context {
                    if let Some(admin) = ctx.reason_admin {
                        println!("-> Reason Admin: {}", admin.message);
                    }
                    if let Some(user) = ctx.reason_user {
                        println!("-> Reason User: {}", user.message);
                    }
                }

                for eval in response.evaluations {
                    if eval.decision {
                        println!("-> ✅ Authorization Permitted");
                    }
                    if let Some(ctx) = eval.context {
                        if let Some(admin) = ctx.reason_admin {
                            println!("-> Reason Admin: {}", admin.message);
                        }
                        if let Some(user) = ctx.reason_user {
                            println!("-> Reason User: {}", user.message);
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to check auth: {}", e);
            return Err(Err(e.into()));
        }
    }
```
