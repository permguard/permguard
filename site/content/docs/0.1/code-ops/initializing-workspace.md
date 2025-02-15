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
**Permguard** provides a **Command Line Interface (CLI)** for managing authentication metadata (**AuthN**)
and authorization metadata and configurations (**AuthZ**) for **Zones**.

- **AuthN administration** is handled through the CLI.
- **AuthZ administration** is managed via both the CLI and the **Policy Language**.

The authorization process follows a **code-first approach**.
When working with **Schemas and Policies**, the CLI must be executed from a **Permguard workspace**
that contains configuration files written in **Cedar**.

## Creating a Permguard Workspace

There are three ways to create a **Permguard workspace** and associate it with a **Permguard ledger**:

1. **Initialize a new ledger** in a Permguard workspace.
2. **Clone an existing ledger** into a Permguard workspace.
3. **Fork an existing ledger** into a working directory.

## Workspace Structure

A **Permguard workspace** contains the following files:

- **Policy files** written in the `Cedar` language.
- A hidden **`.permguard`** directory, used by Permguard to store metadata and intermediate files.
  - This directory is **automatically managed** by Permguard and **should not be modified manually**.
  - It should be added to `.gitignore` to prevent it from being committed to version control.

## Initialize a New Ledger

When starting a new project, the first step is to **create a zone**:

```bash
permguard zones create --name magicfarmacia-dev --output json
```

below is the output of the command:

```bash
{
  "zones": [
    {
      "zone_id": 273165098782,
      "created_at": "2024-08-25T14:07:59.634Z",
      "updated_at": "2024-08-25T14:07:59.634Z",
      "name": "magicfarmacia-dev"
    }
  ]
}
```

Next, create a ledger:

```bash
permguard authz ledgers create --zoneid 273165098782  --name magicfarmacia --output json
```

below is the output of the command:

```bash
{
  "ledgers": [
    {
      "ledger_id": "668f3771eacf4094ba8a80942ea5fd3f",
      "created_at": "2024-08-25T14:50:38.003Z",
      "updated_at": "2024-08-25T14:50:38.003Z",
      "zone_id": 273165098782,
      "name": "magicfarmacia"
    }
  ]
}
```

Finally, initialize the workspace and associate it with a Permguard `remote` server:

```bash
 permguard init
 permguard remote add origin localhost
 permguard checkout origin/273165098782/magicfarmacia
```

## Clone an existing ledger

In advanced cases, a **Permguard ledger** may already exist, and it may be necessary to recover the configuration files to a local **Permguard workspace**.

To do this, simply **clone** the existing **Permguard ledger**:

```bash
permguard clone localhost/273165098782/magicfarmacia
```
