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
weight: 6101
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
  -v, --verbose         true for verbose output

Use "PermGuard authn tenants [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

## Create a Tenant

The `permguard authn tenants create` command allows to create a tenant for the mandatory input account and name.

{{< tabs "permguard-tenants-create" >}}
{{< tab "terminal" >}}

```bash
❯ permguard authn tenants create --account 789251338948 --name permguard
608d3ec8-7c73-4a25-a46c-de2c1425e290: permguard
```

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authn tenants create --account 789251338948 --name permguard --output json
{
  "tenants": [
    {
      "tenant_id": "608d3ec8-7c73-4a25-a46c-de2c1425e290",
      "created_at": "2023-04-01T09:36:11.613499Z",
      "updated_at": "2023-04-01T09:36:11.613499Z",
      "account_id": 789251338948,
      "name": "permguard"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}

## Get All Tenant

The `permguard authn tenants list` command allows for the retrieval of all tenants.

{{< tabs "permguard-tenants-list" >}}
{{< tab "terminal" >}}

```bash
❯ permguard authn tenants list --account 789251338948
667e72d0-a1ad-4e31-8d74-394357b44fbe: default
608d3ec8-7c73-4a25-a46c-de2c1425e290: permguard
```

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authn tenants list --account 789251338948 --output json
{
  "tenants": [
    {
      "tenant_id": "667e72d0-a1ad-4e31-8d74-394357b44fbe",
      "created_at": "2023-04-01T08:27:02.380041Z",
      "updated_at": "2023-04-01T09:20:38.699299Z",
      "account_id": 789251338948,
      "name": "default"
    },
    {
      "tenant_id": "608d3ec8-7c73-4a25-a46c-de2c1425e290",
      "created_at": "2023-04-01T09:36:11.613499Z",
      "updated_at": "2023-04-01T09:36:11.613499Z",
      "account_id": 789251338948,
      "name": "permguard"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}
