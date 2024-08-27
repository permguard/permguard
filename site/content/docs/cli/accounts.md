---
title: "Accounts Management"
description: ""
summary: ""
date: 2023-08-10T20:39:08+01:00
lastmod: 2023-08-10T20:39:08+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "accounts-cc889e190a223318e9616ef4e73dea17"
weight: 6002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `Accounts` commands, it is possible to manage accounts.

```text
This command manages accounts.

Usage:
  PermGuard accounts [flags]
  PermGuard accounts [command]

Available Commands:
  create      Create an account
  delete      Delete an account
  list        List accounts
  update      Update an account

Flags:
  -h, --help   help for accounts

Global Flags:
  -o, --output string   output format (default "terminal")

Use "PermGuard accounts [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

## Create an Account

The `permguard accounts create` command allows to create an account for the input name.

{{< tabs "permguard-accounts-create" >}}
{{< tab "terminal" >}}

```bash
permguard accounts create --name magicfarmacia-dev
```

output:

```bash
 268786704340: magicfarmacia-dev
```

{{< /tab >}}
{{< tab "json" >}}

```bash
permguard accounts create --name magicfarmacia-dev --output json
```

output:

```bash
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

{{< /tab >}}
{{< /tabs >}}

## Fetch Accounts

The `permguard accounts list` command allows for the retrieval of all accounts.

{{< tabs "permguard-accounts" >}}
{{< tab "terminal" >}}

```bash
permguard accounts list
```

output:

```bash
268786704340: magicfarmacia-dev
534434453770: magicfarmacia-uat
627303999986: magicfarmacia-prod
```

{{< /tab >}}
{{< tab "json" >}}

```bash
permguard accounts list --output json
```

output:

```bash
{
  "accounts": [
    {
      "account_id": 268786704340,
      "created_at": "2024-08-25T14:07:07.04Z",
      "updated_at": "2024-08-25T14:07:07.04Z",
      "name": "magicfarmacia-dev"
    },
    {
      "account_id": 534434453770,
      "created_at": "2024-08-25T14:07:59.634Z",
      "updated_at": "2024-08-25T14:07:59.634Z",
      "name": "magicfarmacia-uat"
    },
    {
      "account_id": 627303999986,
      "created_at": "2024-08-25T14:08:58.619Z",
      "updated_at": "2024-08-25T14:08:58.619Z",
      "name": "magicfarmacia-prod"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}
