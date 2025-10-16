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
weight: 6306
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `pull` command, it is possible to fetch the latest changes from the remote ledger and construct the remote state.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command fetches the latest changes from the remote ledger and constructs the remote state.

Examples:
  # fetches the latest changes from the remote ledger and constructs the remote state
  permguard pull

  Find more information at: https://community.permguard.com/docs/0.0.x/command-line/how-to-use/

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

## Pull a ledger

The `permguard pull` command allows you to fetch the latest changes from the remote ledger and construct the remote state.

```bash
permguard pull
```

output:

```bash
The local workspace is already fully up to date with the remote ledger.
Pull process completed successfully.
Your workspace is synchronized with the remote ledger: head/273165098782/9b3de5272b0447f2a8d1024937bdef11.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard pull --output json
```

output:

```json
{
  "code_entries": [
    {
      "code_id": "schema",
      "code_type": "schema",
      "lanaguage_version": "*",
      "language_type": "schema",
      "language": "cedar-json",
      "oid": "007867724d1aa801216d92d8d08ed2269a55e495575aceb1f46cded8594159ee",
      "oname": "schema",
      "type": "blob"
    },
    {
      "code_id": "assign-role-branch",
      "code_type": "policy",
      "lanaguage_version": "*",
      "language_type": "policy",
      "language": "cedar-json",
      "oid": "2597a54653b09188bf613a24e6a64100a1b14612ffed3bd8558dfc24dd63a34f",
      "oname": "assign-role-branch",
      "type": "blob"
    },
    {
      "code_id": "view-branch-inventory-auditors",
      "code_type": "policy",
      "lanaguage_version": "*",
      "language_type": "policy",
      "language": "cedar-json",
      "oid": "553e9dd55b0591930ec043bc89c1a9410d737536e9433c80845bea996d7ca169",
      "oname": "view-branch-inventory-auditors",
      "type": "blob"
    }
  ],
  "local_commit_id": "a73798ba0dc671eac05c1df947e5c5873109117fe149ea9fc84755492e351a47",
  "local_commits_count": 1,
  "remote_commit_id": "a73798ba0dc671eac05c1df947e5c5873109117fe149ea9fc84755492e351a47",
  "remote_commits_count": 1
}
```

</details>
