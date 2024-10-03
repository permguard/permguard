---
title: "Initializing Working Directories"
slug: "Initializing Working Directories"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "initializing-working-directories-8ef0d6939efb49d495094dd500a3f6bb"
weight: 3010
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Permguard provides a Command Line Interface (CLI) for managing authentication metadata (AuthN) and authorization metadata and configurations (AuthZ) for applications.

Authentication is handled exclusively through the CLI, while authorization is managed via both the CLI and the Policy Language.

The authorization process follows a code-first approach, and when dealing with Schemas, Policies, and Permissions, the CLI should be executed from a working directory that contains configuration files written in either YAML or PermScript.

There are three methods to create a working directory and associate it with a Permguard repo:

- Initialize a new repo in a working directory
- Clone an existing repo into a working directory
- Fork an existing repo into a working direct.

## Working directory contents

A `Permguard` working directory contains the following files:

- Configuration files in either `YAML` or `PermScript` format.
- A hidden `.permguard` directory which Permguard uses to store metadata and intermediate files that are automatically managed by Permguard and should not be modified manually. This directory should be added to the `.gitignore` file to prevent it from being committed to the source code version control.

## Initialize a new repo

When starting a new project, the first step is to create an account:

```bash
permguard accounts create --name magicfarmacia-dev --output json
{
  "accounts": [
    {
      "account_id": 268786704340,
      "created_at": "2024-08-25T14:07:59.634Z",
      "updated_at": "2024-08-25T14:07:59.634Z",
      "name": "magicfarmacia-dev"
    }
  ]
}
```

Next, create a repo:

```bash
permguard repositories create --name magicfarmacia-v0.0 --account-id 268786704340  --output json
{
  "repositories": [
    {
      "repo_id": "668f3771eacf4094ba8a80942ea5fd3f",
      "created_at": "2024-08-25T14:50:38.003Z",
      "updated_at": "2024-08-25T14:50:38.003Z",
      "account_id": 268786704340,
      "name": "magicfarmacia-v0.0"
    }
  ]
}
```

Finally, initialize the working directory and associate it with a Permguard `remote` server:

```bash
 permguard init
 permguard remote add dev server.permguard.com
 permguard checkout dev/268786704340/magicfarmacia-v0.0
```

## Clone an existing repo

There are advanced cases where a Permguard repo has already been created and it is required to recovery the configuration files to a local working directory.

In this case, it is just necessary to clone the Permguard repo:

```bash
 permguard clone permguard@server.permguard.com/268786704340/magicfarmacia-v0.0
```
