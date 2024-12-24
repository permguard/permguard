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

  Find more information at: https://www.permguard.com/docs/0.1/using-the-cli/how-to-use/

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
Initiating the planning process for repository head/676095239339/fd1ac44e4afa4fc4beec622494d3175a.
Planning process completed successfully.
The following changes have been identified and are ready to be applied:

	+ 8a169320102ba429b4f7c0a5a9cde6e9bf2ace6335af3b57b11970718c05aa80 view-branch-inventory-auditor
	+ 2597a54653b09188bf613a24e6a64100a1b14612ffed3bd8558dfc24dd63a34f assign-role-branch
	+ 007867724d1aa801216d92d8d08ed2269a55e495575aceb1f46cded8594159ee schema

unchanged 0, created 3, modified 0, deleted 0

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

```json
{
  "plan": {
    "create": [
      {
        "oname": "view-branch-inventory-auditor",
        "otype": "blob",
        "oid": "8a169320102ba429b4f7c0a5a9cde6e9bf2ace6335af3b57b11970718c05aa80",
        "codeid": "view-branch-inventory-auditor",
        "codetype": "policy",
        "language": "cedar-json",
        "languagetype": "policy",
        "languageversion": "*",
        "state": "create"
      },
      {
        "oname": "assign-role-branch",
        "otype": "blob",
        "oid": "2597a54653b09188bf613a24e6a64100a1b14612ffed3bd8558dfc24dd63a34f",
        "codeid": "assign-role-branch",
        "codetype": "policy",
        "language": "cedar-json",
        "languagetype": "policy",
        "languageversion": "*",
        "state": "create"
      },
      {
        "oname": "schema",
        "otype": "blob",
        "oid": "007867724d1aa801216d92d8d08ed2269a55e495575aceb1f46cded8594159ee",
        "codeid": "schema",
        "codetype": "schema",
        "language": "cedar-json",
        "languagetype": "schema",
        "languageversion": "*",
        "state": "create"
      }
    ],
    "delete": [],
    "modify": [],
    "unchanged": []
  }
}
```

</details>
