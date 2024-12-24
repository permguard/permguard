---
title: "Ledgers"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "ledgers-f19c07cf-fbd1-41f0-8220-b17ef0a027f6"
weight: 5202
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `ledgers` command, it is possible to manage Ledgers on the remote server.

```text
This command manages ledgers.

Usage:
  Permguard authz ledgers [flags]
  Permguard authz ledgers [command]

Available Commands:
  create      Create a ledger
  delete      Delete a ledger
  list        List ledgers
  update      Update a ledger

Flags:
      --appid int   application id
  -h, --help          help for ledgers

Global Flags:
  -o, --output string   output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
  -v, --verbose         true for verbose output

Use "Permguard authz ledgers [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Create an Ledger

The `permguard authz ledgers create` command allows to create a ledger for the mandatory input application and name.

```bash
permguard authz ledgers create --appid 268786704340 --name magicfarmacia
```

output:

```bash
668f3771eacf4094ba8a80942ea5fd3f: magicfarmacia
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard authz ledgers create --appid 268786704340 --name magicfarmacia --output json
```

output:

```bash
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

</details>

## Get All Ledgers

The `permguard authz ledgers list` command allows for the retrieval of all ledgers.

```bash
permguard authz ledgers list --appid 268786704340
```

output:

```bash
295433941928473fb692f1a12b6ef660: crm
4fc71b8d934a496d9347ab4a04322460: accounting
668f3771eacf4094ba8a80942ea5fd3f: bookshop
a2b8df4c367940739d872bcbb157155f: insurance
d02af7e50a7b462cb496aa6ddeb4275e: magicfarmacia
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard authz ledgers list --appid 268786704340 --output json
```

output:

```bash
{
  "ledger": [
    {
      "ledger_id": "295433941928473fb692f1a12b6ef660",
      "created_at": "2024-08-25T14:50:30.248Z",
      "updated_at": "2024-08-25T14:50:30.248Z",
      "application_id": 268786704340,
      "name": "crm"
    },
    {
      "ledger_id": "4fc71b8d934a496d9347ab4a04322460",
      "created_at": "2024-08-25T14:50:26.999Z",
      "updated_at": "2024-08-25T14:50:26.999Z",
      "application_id": 268786704340,
      "name": "accounting"
    },
    {
      "ledger_id": "668f3771eacf4094ba8a80942ea5fd3f",
      "created_at": "2024-08-25T14:50:38.003Z",
      "updated_at": "2024-08-25T14:50:38.003Z",
      "application_id": 268786704340,
      "name": "bookshop"
    },
    {
      "ledger_id": "a2b8df4c367940739d872bcbb157155f",
      "created_at": "2024-08-25T14:50:33.046Z",
      "updated_at": "2024-08-25T14:50:33.046Z",
      "application_id": 268786704340,
      "name": "insurance"
    },
    {
      "ledger_id": "d02af7e50a7b462cb496aa6ddeb4275e",
      "created_at": "2024-08-25T14:50:13.705Z",
      "updated_at": "2024-08-25T14:50:13.705Z",
      "application_id": 268786704340,
      "name": "magicfarmacia"
    }
  ]
}
```

</details>
