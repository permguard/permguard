---
title: "History"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "history-8b2b57e6-3aac-4903-8df4-e9ff11d6eaf2"
weight: 6307
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `history` command, it is possible to show the history of the current checked out ledger.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command shows the history.

Examples:
  # show the history
  permguard history

  Find more information at: https://www.permguard.com/docs/0.0.x/command-line/how-to-use/

Usage:
  permguard history [flags]

Flags:
  -h, --help   help for history

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Show the History

The `permguard history` command allows you to show the history of the current checked out ledger.

```bash
permguard history
```

output:

```bash
Your workspace history head/273165098782/fd1ac44e4afa4fc4beec622494d3175a:

commit c813fc8680f0bfc2dc721b383152e163b1afbe5566ef73e1cf6c79862f5e1367:
  - tree: c4107182d88b021fcc36245535e3fdf6a7610374acdcb5b588395912389de5b5
  - Committer date: 2024-12-24 16:51:57 +0100 CET
  - Author date: 2024-12-24 16:51:57 +0100 CET
commit 77a0af3b0189a2bc6e650aa6b0e6ea079b3e96a42290622b608267ca9d57249e:
  - tree: d8a1946ee2c6d16e6b30a16e761d766c46f7ad77a90db2d2522394905184198a
  - Committer date: 2024-12-24 16:50:04 +0100 CET
  - Author date: 2024-12-24 16:50:04 +0100 CET
commit 06e28881c876e9b08c3afb6430b18e85bb2491bf567a40607bd8a57befe82e99:
  - tree: c4107182d88b021fcc36245535e3fdf6a7610374acdcb5b588395912389de5b5
  - Committer date: 2024-12-24 16:48:58 +0100 CET
  - Author date: 2024-12-24 16:48:58 +0100 CET

total 3
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard history --output json
```

output:

```json
{
  "commits": [
    {
      "author": "unknown",
      "author_timestamp": "2024-12-24T16:51:57+01:00",
      "committer": "unknown",
      "committer_timestamp": "2024-12-24T16:51:57+01:00",
      "message": "cli commit",
      "oid": "c813fc8680f0bfc2dc721b383152e163b1afbe5566ef73e1cf6c79862f5e1367",
      "parent": "77a0af3b0189a2bc6e650aa6b0e6ea079b3e96a42290622b608267ca9d57249e",
      "tree": "c4107182d88b021fcc36245535e3fdf6a7610374acdcb5b588395912389de5b5"
    },
    {
      "author": "unknown",
      "author_timestamp": "2024-12-24T16:50:04+01:00",
      "committer": "unknown",
      "committer_timestamp": "2024-12-24T16:50:04+01:00",
      "message": "cli commit",
      "oid": "77a0af3b0189a2bc6e650aa6b0e6ea079b3e96a42290622b608267ca9d57249e",
      "parent": "06e28881c876e9b08c3afb6430b18e85bb2491bf567a40607bd8a57befe82e99",
      "tree": "d8a1946ee2c6d16e6b30a16e761d766c46f7ad77a90db2d2522394905184198a"
    },
    {
      "author": "unknown",
      "author_timestamp": "2024-12-24T16:48:58+01:00",
      "committer": "unknown",
      "committer_timestamp": "2024-12-24T16:48:58+01:00",
      "message": "cli commit",
      "oid": "06e28881c876e9b08c3afb6430b18e85bb2491bf567a40607bd8a57befe82e99",
      "parent": "0000000000000000000000000000000000000000000000000000000000000000",
      "tree": "c4107182d88b021fcc36245535e3fdf6a7610374acdcb5b588395912389de5b5"
    }
  ]
}
```

</details>
