---
title: "Check"
description: ""
summary: ""
date: 2024-12-30T11:00:00+01:00
lastmod: 2024-12-30T11:00:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "check-69711397-a43d-49f2-908d-575e47d68958"
weight: 5203
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `check` command, it is possible to check authz requests.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command checks an authorization request.

Examples:
  # check an authorization request
  permguard authz check --appid 268786704340 --file /path/to/authorization_request.json


  Find more information at: https://www.permguard.com/docs/0.1/using-the-cli/how-to-use/

Usage:
  permguard authz check [flags]

Flags:
      --appid int     application id
  -f, --file string   file containing the authorization request
  -h, --help          help for check

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Check an Authorization Request

The `permguard authz check` command allows to check an authorization request.

```bash
permguard authz check --appid 268786704340 --file /path/to/authorization_request.json
```

output:

```bash
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard authz check --appid 268786704340 --file /path/to/authorization_request.json -o json
```

output:

```json

```
