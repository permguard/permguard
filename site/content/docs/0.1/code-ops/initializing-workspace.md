---
title: "Initializing the Workspace"
slug: "Initializing the Workspace"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "initializing-workspace-8ef0d6939efb49d495094dd500a3f6bb"
weight: 3010
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Permguard provides a Command Line Interface (CLI) for managing authentication metadata (AuthN) and authorization metadata and configurations (AuthZ) for applications.

AuthZ administration is handled exclusively through the CLI, while AuthZ administration is managed via both the CLI and the Policy Language.

The authorization process follows a code-first approach, and when dealing with Schemas and Policies, the CLI should be executed from a permguard workspace that contains configuration files written in Cedar.

There are three methods to create a permguard workspace and associate it with a Permguard ledger:

- Initialize a new ledger in a permguard workspace
- Clone an existing ledger into a permguard workspace
- Fork an existing ledger into a working direct.

## Workspace

A **Permguard** workspace contains the following files:

- Policy files in `Cedar` language.
- A hidden `.permguard` directory which Permguard uses to store metadata and intermediate files that are automatically managed by Permguard and should not be modified manually. This directory should be added to the `.gitignore` file to prevent it from being committed to the source code version control.

## Initialize a new ledger

When starting a new project, the first step is to create an application:

```bash
permguard applications create --name magicfarmacia-dev --output json
{
  "applications": [
    {
      "application_id": 268786704340,
      "created_at": "2024-08-25T14:07:59.634Z",
      "updated_at": "2024-08-25T14:07:59.634Z",
      "name": "magicfarmacia-dev"
    }
  ]
}
```

Next, create a ledger:

```bash
permguard authz  ledgers create --appid 268786704340  --name magicfarmacia --output json
{
  "ledgers": [
    {
      "ledger_id": "668f3771eacf4094ba8a80942ea5fd3f",
      "created_at": "2024-08-25T14:50:38.003Z",
      "updated_at": "2024-08-25T14:50:38.003Z",
      "application_id": 268786704340,
      "name": "magicfarmacia"
    }
  ]
}
```

Finally, initialize the workspace and associate it with a Permguard `remote` server:

```bash
 permguard init
 permguard remote add origin localhost
 permguard checkout origin/676095239339/ledgers/magicfarmacia
```

## Clone an existing ledger

There are advanced cases where a Permguard ledger has already been created and it is required to recovery the configuration files to a local permguard workspace.

In this case, it is just necessary to clone the Permguard ledger:

```bash
 permguard clone permguard@localhost/676095239339/ledgers/magicfarmacia
```
