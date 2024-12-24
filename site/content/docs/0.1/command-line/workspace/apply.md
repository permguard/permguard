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
Initiating the planning process for repository head/676095239339/fd1ac44e4afa4fc4beec622494d3175a.
Planning process completed successfully.
The following changes have been identified and are ready to be applied:

	+ 8a169320102ba429b4f7c0a5a9cde6e9bf2ace6335af3b57b11970718c05aa80 view-branch-inventory-auditor
	+ 2597a54653b09188bf613a24e6a64100a1b14612ffed3bd8558dfc24dd63a34f assign-role-branch
	+ 007867724d1aa801216d92d8d08ed2269a55e495575aceb1f46cded8594159ee schema

unchanged 0, created 3, modified 0, deleted 0

Initiating the apply process for repository head/676095239339/fd1ac44e4afa4fc4beec622494d3175a.
Apply process completed successfully.
Your workspace is synchronized with the remote repository: head/676095239339/fd1ac44e4afa4fc4beec622494d3175a.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard apply --output json
```

output:

```json
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
