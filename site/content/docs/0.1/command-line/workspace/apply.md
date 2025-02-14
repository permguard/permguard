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
weight: 6312
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `apply` command, it is possible to apply the plan to the remote ledger.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command applies the plan to the remote ledger.

Examples:
  # apply the plan to the remote ledger
  permguard apply

  Find more information at: https://www.permguard.com/docs/0.1/command-line/how-to-use/

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

The `permguard apply` command allows you to apply the plan to the remote ledger.

```bash
permguard apply
```

output:

```bash
Initiating the planning process for ledger head/273165098782/fd1ac44e4afa4fc4beec622494d3175a.
Planning process completed successfully.
The following changes have been identified and are ready to be applied:

  + 553e9dd55b0591930ec043bc89c1a9410d737536e9433c80845bea996d7ca169 view-branch-inventory-auditors
  = 64ec643d0775708a947256e8d1eba898a184e9cc8427f9840495e5f5f039e640 assign-role-branch
  = 007867724d1aa801216d92d8d08ed2269a55e495575aceb1f46cded8594159ee schema
  - 8a169320102ba429b4f7c0a5a9cde6e9bf2ace6335af3b57b11970718c05aa80 view-branch-inventory-auditor

unchanged 2, created 1, modified 0, deleted 1

Initiating the apply process for ledger head/273165098782/fd1ac44e4afa4fc4beec622494d3175a.
Apply process completed successfully.
Your workspace is synchronized with the remote ledger: head/273165098782/fd1ac44e4afa4fc4beec622494d3175a.
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
    "create": [],
    "delete": [],
    "modify": [
      {
        "oname": "assign-role-branch",
        "otype": "blob",
        "oid": "2597a54653b09188bf613a24e6a64100a1b14612ffed3bd8558dfc24dd63a34f",
        "codeid": "assign-role-branch",
        "codetype": "policy",
        "language": "cedar-json",
        "languagetype": "policy",
        "languageversion": "*",
        "state": "modify"
      }
    ],
    "unchanged": [
      {
        "oname": "view-branch-inventory-auditors",
        "otype": "blob",
        "oid": "553e9dd55b0591930ec043bc89c1a9410d737536e9433c80845bea996d7ca169",
        "codeid": "view-branch-inventory-auditors",
        "codetype": "policy",
        "language": "cedar-json",
        "languagetype": "policy",
        "languageversion": "*",
        "state": "unchanged"
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
        "state": "unchanged"
      }
    ]
  }
}
```

</details>
