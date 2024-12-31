---
title: "Remote"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "remote-ad6b13c0-27c6-4913-9ecf-852e2762be14"
weight: 5302
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `remote` command, it is possible to manage remote servers.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command manages remote server for tracking and interaction

  Find more information at: https://www.permguard.com/docs/0.1/using-the-cli/how-to-use/

Usage:
  permguard remote [flags]
  permguard remote [command]

Available Commands:
  add         add a new remote ledger to track and interact with
  remove      remove a remote ledger from the configuration

Flags:
  -h, --help   help for remote

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")

Use "permguard remote [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Create a Remote

The `permguard remote add` command allows to add a remote server.

```bash
permguard remote add origin localhost
```

output:

```bash
Remote origin has been added.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard remote add origin localhost --output json
```

output:

```json
{
  "remotes": [
    {
      "aap_port": 9091,
      "aap_server": "localhost",
      "pap_port": 9092,
      "pap_server": "localhost",
      "remote": "origin"
    }
  ]
}
```

</details>

## Get All Remotes

The `permguard remote` command allows for the retrieval of all remote servers.

```bash
permguard remote
```

output:

```bash
Your workspace configured remotes:
  - origin
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard remote --output json
```

output:

```json
{
  "remotes": [
    {
      "aap_port": 9091,
      "aap_server": "localhost",
      "pap_port": 9092,
      "pap_server": "localhost",
      "remote": "origin"
    }
  ]
}
```

</details>
