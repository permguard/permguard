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

This example shows how `MagicFarmacia`, a SaaS pharmacy platform with multiple branches in different cities, uses `PermGuard` for authorization and access control in a `multi-tenant` environment.

## Check Out the Playground

The first step is to check out the `MagicFarmacia` playground.

This example demonstrates PermGuard in action and allows testing of its features.

```shell
git clone git@github.com:permguard/playground-cedar.git
cd playground-cedar
```

## Startup the AuthZ Server

The first operative step is to start the AuthZ server.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Install & Bootstrap](/docs/0.1/getting-started/install-bootstrap/) section for more information about the installation process.
{{< /callout >}}

```shell
docker run --rm -it -p 9091:9091 -p 9092:9092 -p 9094:9094 permguard/demo-all-in-one:latest
```

## Create the Zone and Policy Store

The next step is to create a zone and the policy store.

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [Command Line](/docs/0.1/command-line/how-to-use/) section for more information about the available commands.
{{< /callout >}}

```shell
permguard zones create --name demozone
permguard authz ledgers create --name magicfarmacia --zoneid 386017848379
```

## Checkout and Set Up the Workspace

In this step, you need set up the workspace and check out the policy store.

{{< callout context="note" icon="info-circle" >}}
A workspace represents a local working space. Plese refer to the [CodeOps Workspace](/docs/0.1/code-ops/initializing-the-workspace/) section for more information about the workspace.
{{< /callout >}}

```shell
permguard init
permguard remote add origin localhost
permguard checkout origin/386017848379/magicfarmacia
```

## Apply the Policies

At this stage, since the playground already includes some sample policies, it is necessary to apply the changes.

{{< callout context="note" icon="info-circle" >}}
A workspace represents a local working space. Plese refer to the [CodeOps Coding](/docs/0.1/code-ops/coding/) section for more information about the workspace.
{{< /callout >}}

```shell
permguard apply
```

If everything is set up correctly, you should see the following output:

```shell
❯ permguard apply
Initiating the planning process for ledger head/386017848379/71a73ac8168b4089b1f3e48ba4ac19c6.
Planning process completed successfully.
The following changes have been identified and are ready to be applied:

  + 2c36582597d15df6df4e8b03c4bcae87a92d58a27548291fc92023043e0ee0e2 platform-manager
  + 446f73d58cc36b3b9f2aa644945cfb8fdc92596a5ab6f21ab87e7d1c7461c31b platform-auditor
  + d5a767678430a3ec8d1d6c32764e9f7323987b95337840d8c276345d8f7a1aab anyone-read
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
Plese refer to the [Command Line](/docs/0.1/command-line/authz/check/) section for more information about the available commands.
{{< /callout >}}

```shell
  permguard authz check ./requests/ok_onlyone1.json
```

## Next Steps

{{< callout context="note" icon="info-circle" >}}
Plese refer to the [DevOps](/docs/0.1/devops/authz-server/authorization-server/) section for more information about configuration and deployment.
{{< /callout >}}

The next step is to explore the [Policy as Code](/docs/0.1/policy-as-code/policy-languages/) section to learn more about the policy store and the policy language.
