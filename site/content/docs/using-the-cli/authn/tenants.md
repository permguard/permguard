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
Using the `Tenants` commands, it is possible to manage tenants.

```text
This command manages tenants.

Usage:
  PermGuard authn tenants [flags]
  PermGuard authn tenants [command]

Available Commands:
  create      Create a tenant
  delete      Delete a tenant
  list        List tenants
  update      Update a tenant

Flags:
      --account int   account id filter
  -h, --help          help for tenants

Global Flags:
  -o, --output string   output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
  -v, --verbose         true for verbose output

Use "PermGuard authn tenants [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

## Create a Tenant

The `permguard authn tenants create` command allows to create a tenant for the mandatory input account and name.

```bash
permguard authn tenants create --account 268786704340 --name matera-branch

```

output:

```bash
2e190ee712494838bb54d67e2a0c496a: matera-branch
```

<details>
  <summary>
    JSON Output
  </summary>

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

</details>

## Get All Tenant

The `permguard authn tenants list` command allows for the retrieval of all tenants.

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

<details>
  <summary>
    JSON Output
  </summary>

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

</details>
