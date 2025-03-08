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
    identifier: "azclient-python-sdk-99dc98091354476794598ed5e732b7d8"
weight: 9202
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

```python
with open("./examples/cmd/requests/ok_onlyone1.json", "r") as f:
    json_file = f.read()

az_client = AZClient(with_endpoint("localhost", 9094))

try:
    req = AZRequest.model_validate_json(json_file)
except json.JSONDecodeError:
    print("❌ Authorization request deserialization failed")
    return

decision, response = az_client.check(req)

if decision:
    print("✅ authorization permitted")
else:
    print("❌ authorization denied")
    if response and response.context:
        if response.context.reason_admin:
            print(f"-> reason admin: {response.context.reason_admin.message}")
        if response.context.reason_user:
            print(f"-> reason user: {response.context.reason_user.message}")
        for eval in response.evaluations:
            if eval.context and eval.context.reason_user:
                print(f"-> reason admin: {eval.context.reason_admin.message}")
                print(f"-> reason user: {eval.context.reason_user.message}")
    if response and response.evaluations:
        for eval in response.evaluations:
            if eval.context:
                if eval.context.reason_admin:
                    print(f"-> evaluation requestid {eval.request_id}: reason admin: {eval.context.reason_admin.message}")
                if eval.context.reason_user:
                    print(f"-> evaluation requestid {eval.request_id}: reason user: {eval.context.reason_user.message}")
```

## Perform an Atomic Authorization Request

An `atomic authorization` request can be performed using the `AuthZ Client` by creating a new client instance and invoking the `Check` method.

```python
az_client = AZClient(with_endpoint("localhost", 9094))

principal = PrincipalBuilder("amy.smith@acmecorp.com").build()

entities = [
    {
        "uid": {"type": "MagicFarmacia::Platform::BranchInfo", "id": "subscription"},
        "attrs": {"active": True},
        "parents": [],
    }
]

req = (
    AZAtomicRequestBuilder(
        895741663247,
        "809257ed202e40cab7e958218eecad20",
        "platform-creator",
        "MagicFarmacia::Platform::Subscription",
        "MagicFarmacia::Platform::Action::create",
    )
    .with_request_id("1234")
    .with_principal(principal)
    .with_entities_items("cedar", entities)
    .with_subject_role_actor_type()
    .with_subject_source("keycloack")
    .with_subject_property("isSuperUser", True)
    .with_resource_id("e3a786fd07e24bfa95ba4341d3695ae8")
    .with_resource_property("isEnabled", True)
    .with_action_property("isEnabled", True)
    .with_context_property("time", "2025-01-23T16:17:46+00:00")
    .with_context_property("isSubscriptionActive", True)
    .build()
)

decision, response = az_client.check(req)

if decision:
    print("✅ authorization permitted")
else:
    print("❌ authorization denied")
    if response and response.context:
        if response.context.reason_admin:
            print(f"-> reason admin: {response.context.reason_admin.message}")
        if response.context.reason_user:
            print(f"-> reason user: {response.context.reason_user.message}")
        for eval in response.evaluations:
            if eval.context and eval.context.reason_user:
                print(f"-> reason admin: {eval.context.reason_admin.message}")
                print(f"-> reason user: {eval.context.reason_user.message}")
    if response and response.evaluations:
        for eval in response.evaluations:
            if eval.context:
                if eval.context.reason_admin:
                    print(f"-> evaluation requestid {eval.request_id}: reason admin: {eval.context.reason_admin.message}")
                if eval.context.reason_user:
                    print(f"-> evaluation requestid {eval.request_id}: reason user: {eval.context.reason_user.message}")
```

## Perform a Composed Authorization Request

To perform a composed authorization request using the `AuthZ Client`, you need to create a new client and call the `Check` method.

{{< callout context="note" icon="info-circle" >}}
This type of request is designed for scenarios requiring greater control over the authorization request creation, as well as cases where multiple evaluations must be executed within a single request.
{{< /callout >}}

```python
az_client = AZClient(with_endpoint("localhost", 9094))

subject = (
    SubjectBuilder("platform-creator")
    .with_role_actor_type()
    .with_source("keycloack")
    .with_property("isSuperUser", True)
    .build()
)

resource = (
    ResourceBuilder("MagicFarmacia::Platform::Subscription")
    .with_id("e3a786fd07e24bfa95ba4341d3695ae8")
    .with_property("isEnabled", True)
    .build()
)

action_view = ActionBuilder("MagicFarmacia::Platform::Action::view").with_property("isEnabled", True).build()
action_create = ActionBuilder("MagicFarmacia::Platform::Action::create").with_property("isEnabled", True).build()

context = (
    ContextBuilder()
    .with_property("time", "2025-01-23T16:17:46+00:00")
    .with_property("isSubscriptionActive", True)
    .build()
)

evaluation_view = EvaluationBuilder(subject, resource, action_view).with_request_id("1234").with_context(context).build()
evaluation_create = EvaluationBuilder(subject, resource, action_create).with_request_id("7890").with_context(context).build()

principal = PrincipalBuilder("amy.smith@acmecorp.com").build()

entities = [
    {
        "uid": {"type": "MagicFarmacia::Platform::BranchInfo", "id": "subscription"},
        "attrs": {"active": True},
        "parents": [],
    }
]

req = (
    AZRequestBuilder(895741663247, "809257ed202e40cab7e958218eecad20")
    .with_principal(principal)
    .with_entities_items("cedar", entities)
    .with_evaluation(evaluation_view)
    .with_evaluation(evaluation_create)
    .build()
)

decision, response = az_client.check(req)

if decision:
    print("✅ authorization permitted")
else:
    print("❌ authorization denied")
    if response and response.context:
        if response.context.reason_admin:
            print(f"-> reason admin: {response.context.reason_admin.message}")
        if response.context.reason_user:
            print(f"-> reason user: {response.context.reason_user.message}")
        for eval in response.evaluations:
            if eval.context and eval.context.reason_user:
                print(f"-> reason admin: {eval.context.reason_admin.message}")
                print(f"-> reason user: {eval.context.reason_user.message}")
    if response and response.evaluations:
        for eval in response.evaluations:
            if eval.context:
                if eval.context.reason_admin:
                    print(f"-> evaluation requestid {eval.request_id}: reason admin: {eval.context.reason_admin.message}")
                if eval.context.reason_user:
                    print(f"-> evaluation requestid {eval.request_id}: reason user: {eval.context.reason_user.message}")
```
