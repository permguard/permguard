---
title: "Apply"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "apply-5725b1b4-7645-4bac-b461-773e75f98072"
weight: 5312
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `apply` command, it is possible to apply the plan to the remote repository.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command applies the plan to the remote repository.

Examples:
  # apply the plan to the remote repository
  permguard apply

  Find more information at: https://www.permguard.com/docs/0.1/using-the-cli/how-to-use/

Usage:
  permguard apply [flags]

Flags:
  -h, --help   help for apply

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Apply the local state

The `permguard apply` command allows you to apply the plan to the remote repository.

```bash
permguard apply
```

output:

```bash
Initiating the planning process for repo head/273165098782/9b3de5272b0447f2a8d1024937bdef11.
Planning process completed successfully.
The following changes have been identified and are ready to be applied:

  + 53f1f98089c5b8f9ccbc250c80f1f2d330944009b2a1998375aaef3fb250e10d pharmacy-branch-management1
  = 0a0b9ef638c0ea0e93cf92d6a257dbb4226e42c3eefaba86090870ab2505440a schema
  - 95b32cd25a53e657667c38975c53e2d4a9ad7e8d6f130078cb1ec616b25e506d pharmacy-branch-management

unchanged 1, created 1, modified 0, deleted 1

Initiating the apply process for repo head/273165098782/9b3de5272b0447f2a8d1024937bdef11.
Apply process completed successfully.
Your workspace is synchronized with the remote repository: head/273165098782/9b3de5272b0447f2a8d1024937bdef11.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard apply --output json
```

output:

```bash
{
  "plan": {
    "create": [
      {
        "oname": "pharmacy-branch-management1",
        "otype": "blob",
        "oid": "53f1f98089c5b8f9ccbc250c80f1f2d330944009b2a1998375aaef3fb250e10d",
        "codeid": "pharmacy-branch-management1",
        "codetype": "acpolicy",
        "state": "create"
      }
    ],
    "delete": [
      {
        "oname": "pharmacy-branch-management2",
        "otype": "blob",
        "oid": "9ee3bbbc7fbb2bac3f532cb2b9897293d29d7cdf0bacfc05a5affa11ceb51427",
        "codeid": "pharmacy-branch-management2",
        "codetype": "acpolicy",
        "state": "delete"
      }
    ],
    "modify": [],
    "unchanged": [
      {
        "oname": "schema",
        "otype": "blob",
        "oid": "0a0b9ef638c0ea0e93cf92d6a257dbb4226e42c3eefaba86090870ab2505440a",
        "codeid": "schema",
        "codetype": "schema",
        "state": "unchanged"
      }
    ]
  }
}
```

</details>
