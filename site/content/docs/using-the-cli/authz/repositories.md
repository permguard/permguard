---
title: "Repositories Management"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "repositories-f19c07cf-fbd1-41f0-8220-b17ef0a027f6"
weight: 5202
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `Repositories` commands, it is possible to Manage Repositories on the remote server.

```text
This command manages repositories.

Usage:
  PermGuard authz repos [flags]
  PermGuard authz repos [command]

Available Commands:
  create      Create a repository
  delete      Delete a repository
  list        List repositories
  update      Update a repository

Flags:
      --account int   account id filter
  -h, --help          help for repos

Global Flags:
  -o, --output string   output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
  -v, --verbose         true for verbose output

Use "PermGuard authz repos [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

## Create an Repository

The `permguard authz repos create` command allows to create a repository for the mandatory input account and name.

```bash
permguard authz repos create --account 268786704340 --name v2.0
```

output:

```bash
668f3771eacf4094ba8a80942ea5fd3f: v2.0
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard authz repos create --account 268786704340 --name v2.0 --output json
```

output:

```bash
{
  "repositories": [
    {
      "repository_id": "668f3771eacf4094ba8a80942ea5fd3f",
      "created_at": "2024-08-25T14:50:38.003Z",
      "updated_at": "2024-08-25T14:50:38.003Z",
      "account_id": 268786704340,
      "name": "v2.0"
    }
  ]
}
```

</details>


## Get All Repository

The `permguard authz repos list` command allows for the retrieval of all repositories.

```bash
permguard authz repos list --account 268786704340
```

output:

```bash
295433941928473fb692f1a12b6ef660: v1.2
4fc71b8d934a496d9347ab4a04322460: v1.1
668f3771eacf4094ba8a80942ea5fd3f: v2.0
a2b8df4c367940739d872bcbb157155f: v1.3
d02af7e50a7b462cb496aa6ddeb4275e: v1.0
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard authz repos list --account 268786704340 --output json
```

output:

```bash
{
  "repository": [
    {
      "repository_id": "295433941928473fb692f1a12b6ef660",
      "created_at": "2024-08-25T14:50:30.248Z",
      "updated_at": "2024-08-25T14:50:30.248Z",
      "account_id": 268786704340,
      "name": "v1.2"
    },
    {
      "repository_id": "4fc71b8d934a496d9347ab4a04322460",
      "created_at": "2024-08-25T14:50:26.999Z",
      "updated_at": "2024-08-25T14:50:26.999Z",
      "account_id": 268786704340,
      "name": "v1.1"
    },
    {
      "repository_id": "668f3771eacf4094ba8a80942ea5fd3f",
      "created_at": "2024-08-25T14:50:38.003Z",
      "updated_at": "2024-08-25T14:50:38.003Z",
      "account_id": 268786704340,
      "name": "v2.0"
    },
    {
      "repository_id": "a2b8df4c367940739d872bcbb157155f",
      "created_at": "2024-08-25T14:50:33.046Z",
      "updated_at": "2024-08-25T14:50:33.046Z",
      "account_id": 268786704340,
      "name": "v1.3"
    },
    {
      "repository_id": "d02af7e50a7b462cb496aa6ddeb4275e",
      "created_at": "2024-08-25T14:50:13.705Z",
      "updated_at": "2024-08-25T14:50:13.705Z",
      "account_id": 268786704340,
      "name": "v1.0"
    }
  ]
}
```

</details>
