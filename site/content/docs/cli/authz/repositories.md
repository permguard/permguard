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
weight: 6202
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `Repositories` commands, it is possible to manage repositories.

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
  -v, --verbose         true for verbose output

Use "PermGuard authz repos [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

## Create an Repository

The `permguard authz repos create` command allows to create a repository for the mandatory input account and name.

{{< tabs "permguard-repositories-create" >}}
{{< tab "terminal" >}}

```bash
❯ permguard authz repos create --account 789251338948 --name permguard
```
output:
```
 608d3ec8-7c73-4a25-a46c-de2c1425e290: permguard

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authz repos create --account 789251338948 --name permguard --output json
{
  "repositories": [
    {
      "repository_id": "608d3ec8-7c73-4a25-a46c-de2c1425e290",
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

## Get All Repository

The `permguard authz repos list` command allows for the retrieval of all repositories.

{{< tabs "permguard-repositories-list" >}}
{{< tab "terminal" >}}

```bash
❯ permguard authz repos list --account 789251338948
```
output:
```
 667e72d0-a1ad-4e31-8d74-394357b44fbe: default
 608d3ec8-7c73-4a25-a46c-de2c1425e290: permguard

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authz repos list --account 789251338948 --output json
{
  "repositories": [
    {
      "repository_id": "667e72d0-a1ad-4e31-8d74-394357b44fbe",
      "created_at": "2023-04-01T08:27:02.380041Z",
      "updated_at": "2023-04-01T09:20:38.699299Z",
      "account_id": 789251338948,
      "name": "default"
    },
    {
      "repository_id": "608d3ec8-7c73-4a25-a46c-de2c1425e290",
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
