---
title: "Performing Provisioning"
slug: "Performing Provisioning"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "performing-provisioning-0d5bdf90ebf04870a66f30f93d8ca1af"
weight: 3012
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The primary function of the PermGuard CLI is to create, modify, and destroy schemas, policies, and permissions.

Provisioning in PermGuard involves the process of creating and managing these resources, including schemas, policies, and permissions.

This can primarily be accomplished using the `plan`, `apply`, and `destroy` commands.

## Plan

The `plan` command evaluates the configurations and determines the desired state of all objects (schemas, policies, permissions) to be created, modified, or destroyed on the server.

Essentially, this command compares the current state of the working directory with the server's state and outputs the changes that will be applied.

This command does not apply any changes to the server; it only displays the necessary changes required to achieve the desired state.

```bash
❯ permguard plan
```

## Apply

The `apply` command performs a plan, similar to the `plan` command, but it also applies the changes to the server.

By default, apply performs a `fresh plan` right before applying changes. However, it is possible to apply an existing plan by providing the state file.

```bash
❯ permguard apply
```

## Destroy

The `destroy` command destroys all objects managed by the current working directory.

It uses state data to identify and determine which real-world objects correspond to the managed resources.

```bash
❯ permguard destroy
```
