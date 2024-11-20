---
title: "Pull"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "pull-c76a1dc5-7b0d-4dc8-bee6-96e667ee9601"
weight: 5306
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `Pull` command, it is possible to fetch the latest changes from the remote repository and construct the remote state.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command fetches the latest changes from the remote repository and constructs the remote state.

Examples:
  # fetches the latest changes from the remote repository and constructs the remote state
  permguard pull

	Find more information at: https://www.permguard.com/docs/using-the-cli/how-to-use/

Usage:
  permguard pull [flags]

Flags:
  -h, --help   help for pull

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Pull a repository

The `permguard pull` command allows you to fetch the latest changes from the remote repository and construct the remote state.

```bash
permguard pull
```

output:

```bash
The local workspace is already fully up to date with the remote repository.
Pull process completed successfully.
Your workspace is synchronized with the remote repo: head/273165098782/9b3de5272b0447f2a8d1024937bdef11.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard pull --output json
```

output:

```bash
{
  "pull": [
    {
      "ref": "head/273165098782/9b3de5272b0447f2a8d1024937bdef11"
    }
  ]
}
```

</details>
