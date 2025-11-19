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

```text
permguard zones create --name platform-admin-zone
permguard authz ledgers create --name root --zone-id 357522591679
permguard zones create --name pharmacy-management-zone
permguard authz ledgers create --name root --zone-id 731502230848
permguard zones create --name patient-services-zone
permguard authz ledgers create --name root --zone-id 312332567208
```

Captured output.

```text
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

{{< callout context="caution" icon="info-circle" >}}
Although this example uses explicit roles (e.g. `platform-admin`, `branch-owner`, `pharmacist`) for clarity, **Permguard is not limited to role-based access control (RBAC)**.

In real-world deployments it is possible to model rich authorization using **ABAC**. PharmaAuthZFlow is therefore a **didactic example**, not a limitation of what Permguard can express or enforce.
{{< /callout >}}

---

### 1. Branch Management

This use case covers the administrative workflow of creating and managing pharmacy branches, teams, and roles.

#### Description

- A **Platform Admin** creates a new branch.
- The **Platform Admin** assigns a **Branch Owner** to that branch.
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

- A **Patient** submits a prescription request through the *Prescriptions Service*.
- A **Pharmacist** reviews and validates the prescription.
- Once validated, the *Prescriptions Service* initiates a medication order by calling the *Orders Service*.
- The *Orders Service* checks item availability by querying the *Inventory Service* and temporarily reserves (locks) the medication.
- The **Inventory Operator**, via the *Inventory Service*, reviews stock levels and, if needed, creates a replenishment order.

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

## Workspace Setup & Policy apply for the Platform Administration Zone

In this step, the workspace is set up.

{{< callout context="note" icon="info-circle" >}}
A workspace represents a local working space. Plese refer to the [CodeOps Workspace](/docs/0.0.x/code-ops/initializing-the-workspace/) section for more information about the workspace.
{{< /callout >}}

```text
mkdir -p ./platform-administration-zone && cd ./platform-administration-zone
permguard init --authz-language cedar
permguard remote add origin localhost
permguard checkout origin/312332567208/root
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

Next, policies need to be created and applied to the `root` ledger of the `platform-administration-zone`.
The very first step is to checkout the correct zone and ledger.

```sh
cat << EOD > platform-policies.cedar
@id("branch-administration")
permit(
  principal == Permguard::Identity::Attribute::"role/platform-admin",
  action in [ PharmaAuthZFlow::Platform::Action::"view", PharmaAuthZFlow::Platform::Action::"create",
    PharmaAuthZFlow::Platform::Action::"update", PharmaAuthZFlow::Platform::Action::"delete"],
  resource is PharmaAuthZFlow::Platform::Branch
);

@id("branch-team-management")
permit(
  principal == Permguard::Identity::Attribute::"role/branch-owner",
  action == PharmaAuthZFlow::Platform::Action::"assign-role",
  resource is PharmaAuthZFlow::Platform::Branch
);
EOD
```

Captured output.

```text
permguard checkout origin/895741663247/pharmaauthzflow
Initialized empty permguard ledger in '.'.
Remote origin has been added.
Ledger pharmaauthzflow has been added.
The local workspace is already fully up to date with the remote ledger.
```

At this stage it is time to apply changes to the `root` ledger of the `platform-administration-zone`.

```text
permguard apply
```

Captured output.

```text
❯ permguard apply
Initiating the planning process for ledger head/312332567208/e3de2d340e47406d90fd89d2b4a36974.
Planning process completed successfully.
The following changes have been identified and are ready to be applied:

	+ / 1fa8f770b18e483f662fb3692e6b7bdb54c64a1d071b73c7971a18aa6737bcb1 platform-administration
	+ / bbf799626c4be6f2089d188847f28848844ef655df393607a1f568dcff52e653 branch-administration

unchanged 0, created 2, modified 0, deleted 0

Initiating the apply process for ledger head/312332567208/e3de2d340e47406d90fd89d2b4a36974.
Apply process completed successfully.
Your workspace is synchronized with the remote ledger: head/312332567208/e3de2d340e47406d90fd89d2b4a36974.
```

Policies have now been applied and it is time to perform an authorization check.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Command Line](/docs/0.0.x/command-line/authz/check/) section for more information about the available commands.
{{< /callout >}}

```sh
cat << EOD > authz-request.json
{
  "authorization_model": {
    "zone_id": 357522591679,
    "policy_store": {
      "kind": "ledger",
      "id": "68b7b20034694bd38dd8c1a0254570e0"
    },
    "principal": {
      "type": "workload",
      "id": "spiffe://cluster.local/ns/application/sa/client",
      "source": "ambient-mesh"
    }
  },
  "request_id": "1f12378d138e4c75b70d7cfa32345d39",
  "subject": {
    "type": "attribute",
    "id": "role/branch-owner"
  },
  "resource": {
    "type": "PharmaAuthZFlow::Platform::Branch",
    "id": "fb008a600df04b21841c4fb5ad27ddf7"
  },
  "action": {
    "name": "PharmaAuthZFlow::Platform::Action::assign-role"
  }
}
EOD
```

```text
permguard authz check ./authz-request.json -o json
```

Here’s what gets returned.

```json
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
❯ permguard objects --all
Your workspace objects:

	- 174cfcdf230d433b471839dd2e89776b3babd2eca67b8c11c842013c9ca08ff8 tree
	- 1fa8f770b18e483f662fb3692e6b7bdb54c64a1d071b73c7971a18aa6737bcb1 blob platform-administration
	- 3a49c93fb8795d844d5c86d1441157b90eb94b07f5cab84ee6380861be043eab commit
	- bbf799626c4be6f2089d188847f28848844ef655df393607a1f568dcff52e653 blob branch-administration

total 4, commit 1, tree 1, blob 2
```

The following example shows how to display the content of the `branch-administration` object.

```text
permguard objects cat bbf799626c4be6f2089d188847f28848844ef655df393607a1f568dcff52e653
```

Displayed output.

```text
❯ permguard objects cat bbf799626c4be6f2089d188847f28848844ef655df393607a1f568dcff52e653
Your workspace object bbf799626c4be6f2089d188847f28848844ef655df393607a1f568dcff52e653:

{"annotations":{"id":"branch-administration"},"effect":"permit","principal":{"op":"==","entity":{"type":"Permguard::Identity::Attribute","id":"role/branch-owner"}},"action":{"op":"==","entity":{"type":"PharmaAuthZFlow::Platform::Action","id":"assign-role"}},"resource":{"op":"is","entity_type":"PharmaAuthZFlow::Platform::Subscription"}}

type blob, size 397, oname branch-administration
```

It is also possible to specify the `frontend` option to display the object in a more readable format.

```text
permguard objects cat bbf799626c4be6f2089d188847f28848844ef655df393607a1f568dcff52e653 --frontend
```

Here’s the result.

```text
❯ permguard objects cat bbf799626c4be6f2089d188847f28848844ef655df393607a1f568dcff52e653 --frontend
Your workspace object bbf799626c4be6f2089d188847f28848844ef655df393607a1f568dcff52e653:

@id("branch-administration")
permit (
    principal == Permguard::Identity::Attribute::"role/branch-owner",
    action == PharmaAuthZFlow::Platform::Action::"assign-role",
    resource is PharmaAuthZFlow::Platform::Subscription
);

type blob, size 397, oname branch-administration
```

It is recommended to explore the [Policy as Code](/docs/0.0.x/policy-as-code/policy-languages/) section to learn more about the policy store and the policy language.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [DevOps](/docs/0.0.x/devops/authz-server/authz-server/) section for more information about configuration and deployment.
{{< /callout >}}

Finally, it is worth considering how to deploy the AuthZServer.
