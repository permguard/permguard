---
title: "Hands-on Example"
slug: "Hands-on Example"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "hands-on-example-8c89ddc8339f83444fc4b97264bd5c45"
weight: 1004
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

This example shows how **ZTMedFlow**, a pharmacy management platform with multiple branches across different cities, might use **Permguard** to manage **authorization and access control** in a **multi-tenant, multi-domain** environment.

Each domain (patients, prescriptions, inventory, etc.) maintains its own **ledger**, ensuring isolation per branch, full traceability, and secure access decisions.

| **Domain** | **Ledger** | **What it tracks** |
|----------------|---------------|------------------------|
| **Branch Management** | `branch-management-ledger` | Registration and configuration of pharmacy branches |
| **Patients** | `patient-event-ledger` | Patient data, profile updates, and consent changes |
| **Prescriptions** | `prescription-event-ledger` | Prescription creation and dispensing records |
| **Inventory** | `inventory-transaction-ledger` | Stock movements and restock triggers |
| **Orders** | `order-event-ledger` | Order lifecycle and refund operations |
| **Appointments** | `appointment-ledger` | Bookings and schedule changes |
| **Notifications** | `notification-ledger` | Sent messages and delivery results |

{{< callout context="note" icon="info-circle" >}}
Before to start make sure che [CLI is installed](/docs/0.0.x/getting-started/get-the-cli/)  and the [AuthZServer is running](/docs/0.0.x/getting-started/run-the-authzserver/).
{{< /callout >}}

## Check out the Playground

The first step is to check out the `ZTMedFlow` playground.

This example demonstrates Permguard in action and allows testing of its features.

```text
git clone git@github.com:permguard/playground-server.git
cd playground-server/cedar/ztmedflow/
```

## Create the Zone and Policy Store

The next step is to initialize the workspace then create a zone and the policy store.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Command Line](/docs/0.0.x/command-line/how-to-use/) section for more information about the available commands.
{{< /callout >}}

```text
permguard zones create --name demozone
```

Here’s what you’ll see.

```text
895741663247: demozone
```

It is important to note that the `zoneid` is required for the ledger creation and it is returned by the previous command.

```text
permguard authz ledgers create --name ztmedflow --zone-id 895741663247
```

Displayed result.

```text
809257ed202e40cab7e958218eecad20: ztmedflow
```

## Set Up the Workspace

In this step, you need set up the workspace and check out the policy store.

{{< callout context="note" icon="info-circle" >}}
A workspace represents a local working space. Plese refer to the [CodeOps Workspace](/docs/0.0.x/code-ops/initializing-the-workspace/) section for more information about the workspace.
{{< /callout >}}

```text
permguard init --authz-language cedar
permguard remote add origin localhost
permguard checkout origin/895741663247/ztmedflow
```

Captured output.

```text
permguard remote add origin localhost
permguard checkout origin/895741663247/ztmedflow
Initialized empty permguard ledger in '.'.
Remote origin has been added.
Ledger ztmedflow has been added.
The local workspace is already fully up to date with the remote ledger.
```

## Apply the Policies

At this stage, since the playground already includes some sample policies, it is necessary to apply the changes.

{{< callout context="note" icon="info-circle" >}}
A workspace represents a local working space. Plese refer to the [CodeOps Coding](/docs/0.0.x/code-ops/coding/) section for more information about the workspace.
{{< /callout >}}

```text
permguard apply
```

If everything is set up correctly, you should see the following output.

```text
Initiating the planning process for ledger head/895741663247/809257ed202e40cab7e958218eecad20.
Planning process completed successfully.
The following changes have been identified and are ready to be applied:

  + 2e3d2306e5cae1146396a9c9bf5b1c03c80ede9057d7796f3189a569de4ca113 platform-administrator
  + 3da1ed56372b54f7c6e33b14f21ae3d53db06fe8701b65599c541cbbdf119fde platform-manager
  + b8c072aee9679efdbe86175b51c7305e88e7011e9e8f6f52186ab182b8d0cfa9 platform-auditor
  + f5918d66683fa021e104c8d66d6a9cef4a7a33a3a1d90b5c21043e3d5ece9aec platform-viewer
  + 7fae1224aa4174473d445bb93255c592e66af184fee82956d5ef96a3c55192a1 platform-creator
  + 0bc0aaefc5c96f1ca318c01fef32863273b83c2820ca7f3baf2ddafd73e6ce32 schema

unchanged 0, created 6, modified 0, deleted 0

Initiating the apply process for ledger head/895741663247/809257ed202e40cab7e958218eecad20.
Apply process completed successfully.
Your workspace is synchronized with the remote ledger: head/895741663247/809257ed202e40cab7e958218eecad20.
```

## Perform the Authorization Check

The final step is to perform the authorization check.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Command Line](/docs/0.0.x/command-line/authz/check/) section for more information about the available commands.
{{< /callout >}}

```text
permguard authz check ./requests/ok_onlyone1.json -o json
```

Below a sample json for the authorization check.

```json
{
  "authorization_model": {
    "zone_id": 895741663247,
    "policy_store": {
      "kind": "ledger",
      "id": "809257ed202e40cab7e958218eecad20"
    },
    "principal": {
      "type": "user",
      "id": "amy.smith@acmecorp.com",
      "source": "keycloak"
    },
    "entities": {
      "schema": "cedar",
      "items": [
        {
          "uid": {
            "type": "ZTMedFlow::Platform::BranchInfo",
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
  "request_id": "abc1",
  "subject": {
    "type": "workload",
    "id": "platform-creator",
    "source": "keycloak",
    "properties": {
      "isSuperUser": true
    }
  },
  "resource": {
    "type": "ZTMedFlow::Platform::Subscription",
    "id": "e3a786fd07e24bfa95ba4341d3695ae8",
    "properties": {
      "isEnabled": true
    }
  },
  "action": {
    "name": "ZTMedFlow::Platform::Action::create",
    "properties": {
      "isEnabled": true
    }
  },
  "context": {
    "time": "2025-01-23T16:17:46+00:00",
    "isSubscriptionActive": true
  }
}
```

Here’s what gets returned.

```json
{
  "authorization_check": {
    "request_id": "abc1",
    "decision": true,
    "context": {
      "id": "94acbe8e1f224c6aa7a2e6353ed76869"
    },
    "evaluations": [
      {
        "request_id": "abc1",
        "decision": true,
        "context": {
          "id": "94acbe8e1f224c6aa7a2e6353ed76869"
        }
      }
    ]
  }
}
```

## Next Steps

This example demonstrates how to set up the `ZTMedFlow` playground and perform an authorization check.

To better understand Permguard, it is worth exploring the Policy Store, which is implemented as a Ledger. The Ledger uses a Git-like object storage system.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Command Line Objects](/docs/0.0.x/command-line/workspace/objects/) section for more information about the available commands.
{{< /callout >}}

Below is an example of how to list all objects in the workspace.

```text
permguard objects --all
```

Output shown below.

```text
Your workspace objects:

  - 0bc0aaefc5c96f1ca318c01fef32863273b83c2820ca7f3baf2ddafd73e6ce32 blob schema
  - 2e3d2306e5cae1146396a9c9bf5b1c03c80ede9057d7796f3189a569de4ca113 blob platform-administrator
  - 3da1ed56372b54f7c6e33b14f21ae3d53db06fe8701b65599c541cbbdf119fde blob platform-manager
  - 6a30289b571b09ba52d32b63ff92b745abc8bc8e816f0d585f5a133ee314f652 commit
  - 7fae1224aa4174473d445bb93255c592e66af184fee82956d5ef96a3c55192a1 blob platform-creator
  - b8c072aee9679efdbe86175b51c7305e88e7011e9e8f6f52186ab182b8d0cfa9 blob platform-auditor
  - f5918d66683fa021e104c8d66d6a9cef4a7a33a3a1d90b5c21043e3d5ece9aec blob platform-viewer
  - fb16aa66413ae45275e2063bcbdf6267be4689200b74c04ff8f2ad0f4b03127c tree

total 8, commit 1, tree 1, blob 6
```

The following example shows how to display the content of the `platform-creator` object.

```text
permguard objects cat 7fae1224aa4174473d445bb93255c592e66af184fee82956d5ef96a3c55192a1
```

Displayed output.

```text
Your workspace object 7fae1224aa4174473d445bb93255c592e66af184fee82956d5ef96a3c55192a1:

{"annotations":{"id":"platform-creator"},"effect":"permit","principal":{"op":"==","entity":{"type":"Permguard::Identity::User","id":"platform-creator"}},"action":{"op":"==","entity":{"type":"ZTMedFlow::Platform::Action","id":"create"}},"resource":{"op":"is","entity_type":"ZTMedFlow::Platform::Subscription"},"conditions":[{"kind":"when","body":{"\u0026\u0026":{"left":{"\u0026\u0026":{"left":{"==":{"left":{".":{"left":{"Var":"context"},"attr":"isSubscriptionActive"}},"right":{"Value":true}}},"right":{"==":{"left":{".":{"left":{"Var":"action"},"attr":"isEnabled"}},"right":{"Value":true}}}}},"right":{"==":{"left":{".":{"left":{"Var":"resource"},"attr":"isEnabled"}},"right":{"Value":true}}}}}},{"kind":"unless","body":{"==":{"left":{".":{"left":{"Var":"principal"},"attr":"isSuperUser"}},"right":{"Value":false}}}}]}

type blob, size 881, oname platform-creator
```

It is also possible to specify the `frontend` option to display the object in a more readable format.

```text
permguard objects cat 7fae1224aa4174473d445bb93255c592e66af184fee82956d5ef96a3c55192a1 --frontend
```

Here’s the result.

```text
Your workspace object 7fae1224aa4174473d445bb93255c592e66af184fee82956d5ef96a3c55192a1:

@id("platform-creator")
permit (
    principal == Permguard::Identity::Attribute::"role/platform-creator",
    action == ZTMedFlow::Platform::Action::"create",
    resource is ZTMedFlow::Platform::Subscription
)
when { context.isSubscriptionActive == true && action.isEnabled == true && resource.isEnabled == true }
unless { principal.isSuperUser == false };

type blob, size 881, oname platform-creator
```

It is recommended to explore the [Policy as Code](/docs/0.0.x/policy-as-code/policy-languages/) section to learn more about the policy store and the policy language.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [DevOps](/docs/0.0.x/devops/authz-server/authz-server/) section for more information about configuration and deployment.
{{< /callout >}}

Finally, it is worth considering how to deploy the AuthZServer.
