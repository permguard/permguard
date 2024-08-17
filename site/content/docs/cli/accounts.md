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
❯ permguard accounts create --name prod-corporate
```
output:
```
 664601180677: prod-corporate

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard accounts create --name prod-corporate --output json
{
  "accounts": [
    {
      "account_id": 664601180677,
      "created_at": "2023-08-09T23:26:20.731902Z",
      "updated_at": "2023-08-09T23:26:20.731902Z",
      "name": "prod-corporate"
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
❯ permguard accounts list
```
output:
```
 337648258874: dev-corporate
 996721273374: uat-corporate
 664601180677: prod-corporate

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard accounts list --output json
{
  "accounts": [
    {
      "account_id": 337648258874,
      "created_at": "2023-08-09T15:18:04.849576Z",
      "updated_at": "2023-08-09T15:18:04.849576Z",
      "name": "dev-corporate"
    },
    {
      "account_id": 996721273374,
      "created_at": "2023-08-09T23:26:13.584594Z",
      "updated_at": "2023-08-09T23:26:13.584594Z",
      "name": "uat-corporate"
    },
    {
      "account_id": 664601180677,
      "created_at": "2023-08-09T23:26:20.731902Z",
      "updated_at": "2023-08-09T23:26:20.731902Z",
      "name": "prod-corporate"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}
