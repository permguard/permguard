---
title: "Plan"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "plan-8547c414-d371-42f2-bc0d-1e638146225b"
weight: 5311
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `plan` command, it is possible to  generate a plan of changes to apply to the remote repository based on the differences between the local and remote states.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command generates a plan of changes to apply to the remote repository based on the differences between the local and remote states.

Examples:
  # generate a plan of changes to apply to the remote repository based on the differences between the local and remote states
  permguard plan

	Find more information at: https://www.permguard.com/docs/using-the-cli/how-to-use/

Usage:
  permguard plan [flags]

Flags:
  -h, --help   help for plan

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Plan the local state

The `permguard plan` command allows you to generate a plan of changes to apply to the remote repository based on the differences between the local and remote states.

```bash
permguard plan
```

output:

```bash
Initiating the planning process for repo head/273165098782/9b3de5272b0447f2a8d1024937bdef11.
Planning process completed successfully.
The following changes have been identified and are ready to be applied:

	= 95b32cd25a53e657667c38975c53e2d4a9ad7e8d6f130078cb1ec616b25e506d pharmacy-branch-management
	= 0a0b9ef638c0ea0e93cf92d6a257dbb4226e42c3eefaba86090870ab2505440a schema

unchanged 2, created 0, modified 0, deleted 0

Run the 'apply' command to apply the changes.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard plan --output json
```

output:

```bash
{
  "plan": {
    "create": [],
    "delete": [],
    "modify": [],
    "unchanged": [
      {
        "oname": "pharmacy-branch-management",
        "otype": "blob",
        "oid": "95b32cd25a53e657667c38975c53e2d4a9ad7e8d6f130078cb1ec616b25e506d",
        "codeid": "pharmacy-branch-management",
        "codetype": "acpolicy",
        "state": "unchanged"
      },
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
