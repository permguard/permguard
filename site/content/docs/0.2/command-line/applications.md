---
title: "Applications"
description: ""
summary: ""
date: 2023-08-10T20:39:08+01:00
lastmod: 2023-08-10T20:39:08+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "applications-cc889e190a223318e9616ef4e73dea17"
weight: 5002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `apps` command, it is possible to manage Applications on the remote server.

```text
This command manages applications.

Usage:
  Permguard applications [flags]
  Permguard applications [command]

Available Commands:
  create      Create an application
  delete      Delete an application
  list        List applications
  update      Update an application

Flags:
  -h, --help   help for applications

Global Flags:
  -o, --output string   output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")

Use "Permguard applications [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Create an Application

The `permguard applications create` command allows to create an application for the input name.

```bash
permguard applications create --name magicfarmacia-dev
```

output:

```bash
 268786704340: magicfarmacia-dev
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard applications create --name magicfarmacia-dev --output json
```

output:

```bash
{
  "applications": [
    {
      "application_id": 268786704340,
      "created_at": "2024-08-25T14:07:59.634Z",
      "updated_at": "2024-08-25T14:07:59.634Z",
      "name": "magicfarmacia-dev"
    }
  ]
}
```

</details>

## Fetch Applications

The `permguard applications list` command allows for the retrieval of all applications.

```bash
permguard applications list
```

output:

```bash
268786704340: magicfarmacia-dev
534434453770: magicfarmacia-uat
627303999986: magicfarmacia-prod
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard applications list --output json
```

output:

```bash
{
  "applications": [
    {
      "application_id": 268786704340,
      "created_at": "2024-08-25T14:07:07.04Z",
      "updated_at": "2024-08-25T14:07:07.04Z",
      "name": "magicfarmacia-dev"
    },
    {
      "application_id": 534434453770,
      "created_at": "2024-08-25T14:07:59.634Z",
      "updated_at": "2024-08-25T14:07:59.634Z",
      "name": "magicfarmacia-uat"
    },
    {
      "application_id": 627303999986,
      "created_at": "2024-08-25T14:08:58.619Z",
      "updated_at": "2024-08-25T14:08:58.619Z",
      "name": "magicfarmacia-prod"
    }
  ]
}
```

</details>
