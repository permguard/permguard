---
title: "Repo"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "repo-f801b840-8650-43e7-90e4-d9344e3f6e06"
weight: 5304
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Using the `repos` command, it is possible to manage locally checked out repositories.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command manages repository settings and operations.

  Find more information at: https://www.permguard.com/docs/0.1/using-the-cli/how-to-use/

Usage:
  permguard repos [flags]

Flags:
  -h, --help   help for repo

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Get All Repos

The `permguard repos` command allows for the retrieval of all locally checked out repositories.

```bash
permguard repos
```

output:

```bash
Your workspace configured repositories:

  - *origin/273165098782/magicfarmacia

```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard repos --output json
```

output:

```json
{
  "repos": [
    {
      "is_head": true,
      "ref": "refs/remotes/origin/676095239339/fd1ac44e4afa4fc4beec622494d3175a",
      "repo_id": "fd1ac44e4afa4fc4beec622494d3175a",
      "repo_uri": "origin/676095239339/branches"
    }
  ]
}
```

</details>
