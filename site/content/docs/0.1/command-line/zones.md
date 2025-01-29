---
title: "Zones"
description: ""
summary: ""
date: 2023-08-10T20:39:08+01:00
lastmod: 2023-08-10T20:39:08+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "zones-cc889e190a223318e9616ef4e73dea17"
weight: 6002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `zone` command, it is possible to manage Zones on the remote server.

```text
This command manages zones.

Usage:
  Permguard zone [flags]
  Permguard zone [command]

Available Commands:
  create      Create a zone
  delete      Delete a zone
  list        List zones
  update      Update a zone

Flags:
  -h, --help   help for zones

Global Flags:
  -o, --output string   output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")

Use "Permguard zone [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Create a zone

The `permguard zones create` command allows to create a zone for the input name.

```bash
permguard zones create --name magicfarmacia-dev
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
permguard zones create --name magicfarmacia-dev --output json
```

output:

```bash
{
  "zones": [
    {
      "zone_id": 268786704340,
      "created_at": "2024-08-25T14:07:59.634Z",
      "updated_at": "2024-08-25T14:07:59.634Z",
      "name": "magicfarmacia-dev"
    }
  ]
}
```

</details>

## Fetch Zones

The `permguard zones list` command allows for the retrieval of all zones.

```bash
permguard zones list
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
permguard zones list --output json
```

output:

```bash
{
  "zones": [
    {
      "zone_id": 268786704340,
      "created_at": "2024-08-25T14:07:07.04Z",
      "updated_at": "2024-08-25T14:07:07.04Z",
      "name": "magicfarmacia-dev"
    },
    {
      "zone_id": 534434453770,
      "created_at": "2024-08-25T14:07:59.634Z",
      "updated_at": "2024-08-25T14:07:59.634Z",
      "name": "magicfarmacia-uat"
    },
    {
      "zone_id": 627303999986,
      "created_at": "2024-08-25T14:08:58.619Z",
      "updated_at": "2024-08-25T14:08:58.619Z",
      "name": "magicfarmacia-prod"
    }
  ]
}
```

</details>
