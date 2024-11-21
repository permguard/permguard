---
title: "Checkout"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "checkout-f19c07cf-fbd1-41f0-8220-b17ef0a027f6"
weight: 5303
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `checkout` command, it is possible to checkout out a remote repository locally.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command checks out the contents of a remote repository to the local working directory.

Examples:
  # check out the contents of a remote repository to the local working directory
  permguard checkout dev/268786704340/magicfarmacia-v0.0

  Find more information at: https://www.permguard.com/docs/0.1/using-the-cli/how-to-use/

Usage:
  permguard checkout [flags]

Flags:
  -h, --help   help for checkout

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Checkout a repository

The `permguard checkout` command allows you to check out a remote repository locally.

```bash
permguard checkout origin/273165098782/v1.0
```

output:

```bash
Repo v1.0 has been added.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard checkout origin/273165098782/v1.0 --output json
```

output:

```bash
{
  "repos": [
    {
      "repo": "v1.0"
    }
  ]
}
```

</details>
