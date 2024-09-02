---
title: "Tenants Management"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "tenants-c8cedcba-38bd-4afb-9fbb-e3ce1d23c8bb"
weight: 5101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
   ____                      ____                     _
  |  _ \ ___ _ __ _ __ ___  / ___|_   _  __ _ _ __ __| |
  | |_) / _ \ '__| '_ ` _ \| |  _| | | |/ _` | '__/ _` |
  |  __/  __/ |  | | | | | | |_| | |_| | (_| | | | (_| |
  |_|   \___|_|  |_| |_| |_|\____|\__,_|\__,_|_|  \__,_|

The official PermGuard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

PermGuard is an Open Source Multi-Account and Multi-Tenant Authorization Provider.

  Find more information at: https://www.permguard.com/docs/cli/how-to-use/

Usage:
  PermGuard Command Line Interface [flags]
  PermGuard [command]

Available Commands:
  accounts    Manage accounts on the remote server
  apply       Apply the plan to the remote repo
  authn       Manage tenants and identities on the remote server
  authz       Manage repositories on the remote server
  checkout    Checkout a repo
  clone       Clone an existing repo from a remote into the working directory
  completion  Generate the autocompletion script for the specified shell
  config      Configure the command line settings
  destroy     Destroy objects in the remote repo
  diff        Calculate the difference between the working directory and a remote repo
  help        Help about any command
  init        Initialize a new repository in the working directory
  plan        Plan the difference between the working directory and a remote repo to be applied
  pull        Feteches the latest changes from the server and build a remote state
  remote      Manage the set of remote servers you track
  repo        Manage the local repo
  validate    Validate source code in the working directory

Flags:
  -h, --help             help for PermGuard
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")

Use "PermGuard [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

## Create a Tenant

The `permguard authn tenants create` command allows to create a tenant for the mandatory input account and name.

{{< tabs "permguard-tenants-create" >}}
{{< tab "terminal" >}}

```bash
permguard authn tenants create --account 268786704340 --name matera-branch

```

output:

```bash
2e190ee712494838bb54d67e2a0c496a: matera-branch
```

{{< /tab >}}
{{< tab "json" >}}

```bash
permguard authn tenants create --account 268786704340 --name matera-branch --output json
```

output:

```bash
{
  "tenant": [
    {
      "tenant_id": "2e190ee712494838bb54d67e2a0c496a",
      "created_at": "2024-08-25T14:14:33.794Z",
      "updated_at": "2024-08-25T14:14:33.794Z",
      "account_id": 268786704340,
      "name": "matera-branch"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}

## Fetch Tenant

The `permguard authn tenants list` command allows for the retrieval of all tenants.

{{< tabs "permguard-tenants-list" >}}
{{< tab "terminal" >}}

```bash
permguard authn tenants list --account 268786704340

```

output:

```bash
0f85cbd14e3f462882f0e09d9f64ff40: london-branch
1fb7c545dce74cb18b2e4896d3e9a96e: leeds-branch
2e190ee712494838bb54d67e2a0c496a: matera-branch
51548dac972c4df183b312a3b665e8e2: pisa-branch
59c3f233d0a0447fb2a977ad9605d12c: bari-branch
aca65c4dea4d488ab5a52b63b0ba25ef: milan-branch
ec40fe0ce651404a8cc0e4ab1e386053: birmingham-branch
```

{{< /tab >}}
{{< tab "json" >}}

```bash
permguard authn tenants list --account 268786704340 --output json
```

output:

```bash
{
  "tenant": [
    {
      "tenant_id": "0f85cbd14e3f462882f0e09d9f64ff40",
      "created_at": "2024-08-25T14:16:43.778Z",
      "updated_at": "2024-08-25T14:16:43.778Z",
      "account_id": 268786704340,
      "name": "london-branch"
    },
    {
      "tenant_id": "1fb7c545dce74cb18b2e4896d3e9a96e",
      "created_at": "2024-08-25T14:16:44.802Z",
      "updated_at": "2024-08-25T14:16:44.802Z",
      "account_id": 268786704340,
      "name": "leeds-branch"
    },
    {
      "tenant_id": "2e190ee712494838bb54d67e2a0c496a",
      "created_at": "2024-08-25T14:14:33.794Z",
      "updated_at": "2024-08-25T14:14:33.794Z",
      "account_id": 268786704340,
      "name": "matera-branch"
    },
    {
      "tenant_id": "51548dac972c4df183b312a3b665e8e2",
      "created_at": "2024-08-25T14:16:41.657Z",
      "updated_at": "2024-08-25T14:16:41.657Z",
      "account_id": 268786704340,
      "name": "pisa-branch"
    },
    {
      "tenant_id": "59c3f233d0a0447fb2a977ad9605d12c",
      "created_at": "2024-08-25T14:16:42.753Z",
      "updated_at": "2024-08-25T14:16:42.753Z",
      "account_id": 268786704340,
      "name": "bari-branch"
    },
    {
      "tenant_id": "aca65c4dea4d488ab5a52b63b0ba25ef",
      "created_at": "2024-08-25T14:16:40.585Z",
      "updated_at": "2024-08-25T14:16:40.585Z",
      "account_id": 268786704340,
      "name": "milan-branch"
    },
    {
      "tenant_id": "ec40fe0ce651404a8cc0e4ab1e386053",
      "created_at": "2024-08-25T14:16:45.815Z",
      "updated_at": "2024-08-25T14:16:45.815Z",
      "account_id": 268786704340,
      "name": "birmingham-branch"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}
