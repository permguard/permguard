---
title: "Setting up a Workspace"
slug: "Setting up a Workspace"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "setting-up-workspace-8ef0d6939efb49d495094dd500a3f6bb"
weight: 3010
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

This guide will help you quickly set up a workspace in `PermGuard` to manage your code.

## Account and  Repository creation

The very first step is to create an account and a repository. You can create an account using the `PermGuard` CLI.

```bash
❯ permguard accounts create --name magicfarmacia-dev
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

Next, create a repository using the `PermGuard` CLI.

```bash
❯ permguard repositories create --name magicfarmacia-v0.0 --account-id 268786704340
{
  "repositories": [
    {
      "repository_id": "668f3771eacf4094ba8a80942ea5fd3f",
      "created_at": "2024-08-25T14:50:38.003Z",
      "updated_at": "2024-08-25T14:50:38.003Z",
      "account_id": 268786704340,
      "name": "magicfarmacia-v0.0"
    }
  ]
}
```

## Clone the Repository

Ideally, the next step is to clone a Git repository to manage your code. However, this step is optional—you can also choose to save your work locally.

```bash
❯ git clone git@github.com:permguard/magicfarmacia.git
```

Finally it is required to clone the `PermGuard` repository to your local machine.

```bash
❯ permguard clone --account 268786704340
```
