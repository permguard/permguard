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
Using the `checkout` command, it is possible to checkout out a remote ledger locally.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command checks out the contents of a remote ledger to the local permguard workspace.

Examples:
  # check out the contents of a remote ledger to the local permguard workspace
  permguard checkout origin/676095239339/ledgers/magicfarmacia

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

## Checkout a ledger

The `permguard checkout` command allows you to check out a remote ledger locally.

```bash
permguard checkout origin/676095239339/ledgers/magicfarmacia
```

output:

```bash
Ledger magicfarmacia has been added.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard checkout origin/676095239339/ledgers/magicfarmacia --output json
```

output:

```json
{
  "ledgers": [
    {
      "is_head": true,
      "ref": "refs/remotes/origin/676095239339/fd1ac44e4afa4fc4beec622494d3175a",
      "ledger_id": "fd1ac44e4afa4fc4beec622494d3175a",
      "ledger_uri": "origin/676095239339/branches"
    }
  ]
}
```

</details>
