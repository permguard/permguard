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
weight: 1005
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

This example shows how `MagicFarmacia`, a SaaS pharmacy platform with multiple branches in different cities, uses `Permguard` for authorization and access control in a `multi-tenant` environment.

## Check out the Playground

The first step is to check out the `MagicFarmacia` playground.

This example demonstrates Permguard in action and allows testing of its features.

```text
git clone git@github.com:permguard/playground-cedar.git
cd playground-cedar
```

## Configure Users, Actors and Tenants

The next step is to configure the users and actors.

```text
permguard authn identitysources create --name keycloak --zoneid 108842867481
permguard authn identities create --name amy.smith@acmecorp.com --kind user --identitysourceid 377e73eb2b3c48f3be9e03a7caa4046f --zoneid 108842867481
permguard authn identities create --name platform-admin --kind actor --identitysourceid 377e73eb2b3c48f3be9e03a7caa4046f --zoneid 108842867481
permguard authn tenants create --name matera-branch --zoneid 108842867481
permguard authn tenants create --name pisa-branch --zoneid 108842867481

```

## Start up the AuthZ Server

The first operative step is to start the AuthZ server.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Install & Bootstrap](/docs/0.1.x/getting-started/install-bootstrap/) section for more information about the installation process.
{{< /callout >}}

```text
docker run --rm -it -p 9091:9091 -p 9092:9092 -p 9094:9094 permguard/demo-all-in-one:latest
```

## Create the Zone and Policy Store

The next step is to create a zone and the policy store.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Command Line](/docs/0.1.x/command-line/how-to-use/) section for more information about the available commands.
{{< /callout >}}

```text
permguard zones create --name demozone
```

It is important to note that the `zoneid` is required for the policy store creation and it is returned by the previous command.

```text
permguard authz ledgers create --name magicfarmacia --zoneid 386017848379
```

## Set Up the Workspace

In this step, you need set up the workspace and check out the policy store.

{{< callout context="note" icon="info-circle" >}}
A workspace represents a local working space. Plese refer to the [CodeOps Workspace](/docs/0.1.x/code-ops/initializing-the-workspace/) section for more information about the workspace.
{{< /callout >}}

```text
permguard init
permguard remote add origin localhost
permguard checkout origin/386017848379/magicfarmacia
```

## Apply the Policies

At this stage, since the playground already includes some sample policies, it is necessary to apply the changes.

{{< callout context="note" icon="info-circle" >}}
A workspace represents a local working space. Plese refer to the [CodeOps Coding](/docs/0.1.x/code-ops/coding/) section for more information about the workspace.
{{< /callout >}}

```text
permguard apply
```

If everything is set up correctly, you should see the following output.

```text
❯ permguard apply
Initiating the planning process for ledger head/386017848379/71a73ac8168b4089b1f3e48ba4ac19c6.
Planning process completed successfully.
The following changes have been identified and are ready to be applied:

  + 2c36582597d15df6df4e8b03c4bcae87a92d58a27548291fc92023043e0ee0e2 platform-manager
  + 446f73d58cc36b3b9f2aa644945cfb8fdc92596a5ab6f21ab87e7d1c7461c31b platform-auditor
  + d5a767678430a3ec8d1d6c32764e9f7323987b95337840d8c276345d8f7a1aab platform-view
  + 6b9215b4696f02629f2eac4a039840a8ed46a9f31e6bfe89d3b8e6f6b6c4b23e platform-creator
  + ba402e8797e48b8d36a029632c150fbe4d873b3dcd075d7fc52420c4c919339a platform-administrator
  + 0bc0aaefc5c96f1ca318c01fef32863273b83c2820ca7f3baf2ddafd73e6ce32 schema

unchanged 0, created 6, modified 0, deleted 0

Initiating the apply process for ledger head/386017848379/71a73ac8168b4089b1f3e48ba4ac19c6.
Apply process completed successfully.
Your workspace is synchronized with the remote ledger: head/386017848379/71a73ac8168b4089b1f3e48ba4ac19c6.
```

## Perform the Authorization Check

The final step is to perform the authorization check.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Command Line](/docs/0.1.x/command-line/authz/check/) section for more information about the available commands.
{{< /callout >}}

```text
  permguard authz check ./requests/ok_onlyone1.json
```

Below a sample json for the authorization check.

```json
{
  "authorization_model": {
    "zone_id": 979783680014,
    "policy_store": {
      "type": "ledger",
      "id": "ce5b5ec4eed64d0c906f08b69a22ee7b"
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
            "type": "MagicFarmacia::Platform::BranchInfo",
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
    "type": "actor",
    "id": "platform-admin",
    "source": "keycloak",
    "properties": {
      "isSuperUser": true
    }
  },
  "resource": {
    "type": "MagicFarmacia::Platform::Subscription",
    "id": "e3a786fd07e24bfa95ba4341d3695ae8",
    "properties": {
      "isEnabled": true
    }
  },
  "action": {
    "name": "MagicFarmacia::Platform::Action::view",
    "properties": {
      "isEnabled": true
    }
  },
  "context": {
    "time": "2025-01-23T16:17:46+00:00",
    "isSubscriptionActive": false
  }
}
```

## Next Steps

This example demonstrates how to set up the `MagicFarmacia` playground and perform an authorization check.

To better understand Permguard, it is worth exploring the Policy Store, which is implemented as a Ledger. The Ledger uses a Git-like object storage system.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Command Line Objects](/docs/0.1.x/command-line/workspace/objects/) section for more information about the available commands.
{{< /callout >}}

Below is an example of how to list all objects in the workspace:

```text
❯ permguard objects --all
Your workspace objects:

  - 0bc0aaefc5c96f1ca318c01fef32863273b83c2820ca7f3baf2ddafd73e6ce32 blob schema
  - 2c36582597d15df6df4e8b03c4bcae87a92d58a27548291fc92023043e0ee0e2 blob platform-manager
  - 4415e2859d5267db9509f8b7d64bb1b2e3684ee85170474383340ea77bb16919 commit
  - 446f73d58cc36b3b9f2aa644945cfb8fdc92596a5ab6f21ab87e7d1c7461c31b blob platform-auditor
  - 6b9215b4696f02629f2eac4a039840a8ed46a9f31e6bfe89d3b8e6f6b6c4b23e blob platform-creator
  - ba402e8797e48b8d36a029632c150fbe4d873b3dcd075d7fc52420c4c919339a blob platform-administrator
  - cdcd1ea6a74a41ce5a61f4d556c1d15bde70660928ad5d57aa84834a3a01f291 tree
  - d5a767678430a3ec8d1d6c32764e9f7323987b95337840d8c276345d8f7a1aab blob platform-view

total 8, commit 1, tree 1, blob 6
```

The following example shows how to display the content of the `platform-manager` object.

```text
❯ permguard objects cat 2c36582597d15df6df4e8b03c4bcae87a92d58a27548291fc92023043e0ee0e2
Your workspace object 2c36582597d15df6df4e8b03c4bcae87a92d58a27548291fc92023043e0ee0e2:

{"annotations":{"id":"platform-manager"},"effect":"permit","principal":{"op":"in","entity":{"type":"Permguard::IAM::Actor","id":"platform-admin"}},"action":{"op":"in","entities":[{"type":"MagicFarmacia::Platform::Action","id":"view"},{"type":"MagicFarmacia::Platform::Action","id":"update"}]},"resource":{"op":"==","entity":{"type":"MagicFarmacia::Platform::Subscription","id":"e3a786fd07e24bfa95ba4341d3695ae8"}},"conditions":[{"kind":"unless","body":{"\u0026\u0026":{"left":{"has":{"left":{"Var":"principal"},"attr":"isSuperUser"}},"right":{"==":{"left":{".":{"left":{"Var":"principal"},"attr":"isSuperUser"}},"right":{"Value":false}}}}}}]}

type blob, size 695, oname platform-manager
```

It is also possible to specify the `frontend` option to display the object in a more readable format.

```text
❯ permguard objects cat 2c36582597d15df6df4e8b03c4bcae87a92d58a27548291fc92023043e0ee0e2 --frontend
Your workspace object 2c36582597d15df6df4e8b03c4bcae87a92d58a27548291fc92023043e0ee0e2:

@id("platform-manager")
permit (
    principal in Permguard::IAM::Actor::"platform-admin",
    action in [MagicFarmacia::Platform::Action::"view", MagicFarmacia::Platform::Action::"update"],
    resource == MagicFarmacia::Platform::Subscription::"e3a786fd07e24bfa95ba4341d3695ae8"
)
unless { principal has isSuperUser && principal.isSuperUser == false };

type blob, size 695, oname platform-manager
```

It is recommended to explore the [Policy as Code](/docs/0.1.x/policy-as-code/policy-languages/) section to learn more about the policy store and the policy language.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [DevOps](/docs/0.1.x/devops/authz-server/authz-server/) section for more information about configuration and deployment.
{{< /callout >}}

Finally, it is worth considering how to deploy the AuthZ server.
