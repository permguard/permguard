---
title: "Hands-on Base Example"
slug: "Hands-on Base Example"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "hands-on-base-example-8c89ddc8339f83444fc4b97264bd5c45"
weight: 1004
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
## PharmaAuthZFlow Example

The **PharmaAuthZFlow** example demonstrates how `Permguard` enforces authorization across the distinct trust boundaries of a pharmacy ecosystem.

It shows how `users`, `workloads`, and `roles` interact within a Zero Trust authorization model.

The example is intentionally simplified to highlight core authorization concepts across **three main domains**:

- **Platform-Administration Domain**
  Manages the pharmacy franchise: branches, teams, roles, and administrative operations.

- **Operations-Management Domain**
  Handles operational workflows: medication orders, fulfillment, stock levels, inventory and logistics.

- **Patient-Services Domain**
  Covers clinical workflows: patients, prescriptions, medication requests, dispensing, appointments, and notifications.

Each domain represents its own bounded context (trusted boundary).
In real-world environments, these domains would likely be further segmented, but here we keep the model intentionally simple.

Therefore, each domain requires its own Permguard `zone` and a `root` ledger for managing policies.

{{< callout context="note" icon="info-circle" >}}
Before proceeding, ensure the [CLI is installed](/docs/0.0.x/getting-started/get-the-cli/) and the [AuthZServer is running](/docs/0.0.x/getting-started/run-the-authzserver/).
{{< /callout >}}

---

## Creating the Zones and Ledgers

The first step is to **segment the trust boundaries** using `Permguard zones`, and create a dedicated `ledger` for each one.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/pharmaazflow-segments.png"/>
</div>

{{< callout context="note" icon="info-circle" >}}
Permguard conventionally names the main ledger of a zone `root`, representing the primary policy store of that zone.
{{< /callout >}}

Let's create the zones and their `root` ledgers:

```sh
❯ permguard zones create --name platform-admin-zone
357522591679: platform-admin-zone
❯ permguard authz ledgers create --name root --zone-id 357522591679
68b7b20034694bd38dd8c1a0254570e0: root
❯ permguard zones create --name pharmacy-management-zone
731502230848: pharmacy-management-zone
❯ permguard authz ledgers create --name root --zone-id 731502230848
cb275322b8ae4b6f8f540d7601dee8ed: root
❯ permguard zones create --name patient-services-zone
312332567208: patient-services-zone
❯ permguard authz ledgers create --name root --zone-id 312332567208
e3de2d340e47406d90fd89d2b4a36974: root
```

## Use Cases, Roles, and Architectural Components

In this example, we implement **two main use cases**:

1. **Branch Management**
2. **Prescription and Medication Order Flow**

Each use case spans multiple roles, services, and trusted zones within the PharmaAuthZFlow architecture.

<div style="text-align: center">
  <img alt="Permguard" src="/images/diagrams/pharmaazflow-components.png"/>
</div>

---

### 1. Branch Management

This use case covers the administrative workflow of creating and managing pharmacy branches, teams, and roles.

#### Description

- A **Platform Admin** creates a new branch.
- The admin assigns a **Branch Owner** to that branch.
- The **Branch Owner** configures the local team and assigns roles such as *pharmacist* or *inventory-operator*.

#### Roles

| Role             | Description                                    |
|------------------|------------------------------------------------|
| `platform-admin` | Manages global franchise-level operations       |
| `branch-owner`   | Manages branch-level team and role assignments  |

#### Services & Zones

| Zone                           | Service             | Purpose                                  |
|--------------------------------|---------------------|------------------------------------------|
| `platform-administration-zone` | `platform-service`  | Branch creation, user/role assignment    |

---

### 2. Prescription & Medication Order Flow

This use case covers the clinical workflow from prescription creation to medication ordering and stock verification.

#### Description

- A **Patient** submits a prescription request.
- A **Pharmacist** validates the request.
- The **Pharmacist** triggers an order through the *Orders Service*.
- The **Inventory Operator** checks stock via the *Inventory Service* and orders medication if needed.

#### Roles

| Role                 | Description                                      |
|----------------------|--------------------------------------------------|
| `patient`            | Requests prescriptions                            |
| `pharmacist`         | Validates prescriptions and places medication orders |
| `inventory-operator` | Verifies stock and handles inventory ordering    |

#### Services & Zones

| Zone                        | Service                | Purpose                                     |
|-----------------------------|------------------------|---------------------------------------------|
| `patient-services-zone`     | `prescriptions-service`| Handles prescription submissions             |
| `operations-management-zone`| `orders-service`       | Orders medications from suppliers            |
| `operations-management-zone`| `inventory-service`    | Checks and updates medication inventory      |

## Set Up the Workspace

In this step, you need set up the workspace and check out the policy store.

{{< callout context="note" icon="info-circle" >}}
A workspace represents a local working space. Plese refer to the [CodeOps Workspace](/docs/0.0.x/code-ops/initializing-the-workspace/) section for more information about the workspace.
{{< /callout >}}

```text
permguard init --authz-language cedar
permguard remote add origin localhost
permguard checkout origin/895741663247/pharmaauthzflow
```

Captured output.

```text
permguard remote add origin localhost
permguard checkout origin/895741663247/pharmaauthzflow
Initialized empty permguard ledger in '.'.
Remote origin has been added.
Ledger pharmaauthzflow has been added.
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
            "type": "PharmaAuthZFlow::Platform::BranchInfo",
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
    "type": "PharmaAuthZFlow::Platform::Subscription",
    "id": "e3a786fd07e24bfa95ba4341d3695ae8",
    "properties": {
      "isEnabled": true
    }
  },
  "action": {
    "name": "PharmaAuthZFlow::Platform::Action::create",
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

This example demonstrates how to set up the `PharmaAuthZFlow` playground and perform an authorization check.

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

{"annotations":{"id":"platform-creator"},"effect":"permit","principal":{"op":"==","entity":{"type":"Permguard::Identity::User","id":"platform-creator"}},"action":{"op":"==","entity":{"type":"PharmaAuthZFlow::Platform::Action","id":"create"}},"resource":{"op":"is","entity_type":"PharmaAuthZFlow::Platform::Subscription"},"conditions":[{"kind":"when","body":{"\u0026\u0026":{"left":{"\u0026\u0026":{"left":{"==":{"left":{".":{"left":{"Var":"context"},"attr":"isSubscriptionActive"}},"right":{"Value":true}}},"right":{"==":{"left":{".":{"left":{"Var":"action"},"attr":"isEnabled"}},"right":{"Value":true}}}}},"right":{"==":{"left":{".":{"left":{"Var":"resource"},"attr":"isEnabled"}},"right":{"Value":true}}}}}},{"kind":"unless","body":{"==":{"left":{".":{"left":{"Var":"principal"},"attr":"isSuperUser"}},"right":{"Value":false}}}}]}

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
    action == PharmaAuthZFlow::Platform::Action::"create",
    resource is PharmaAuthZFlow::Platform::Subscription
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
