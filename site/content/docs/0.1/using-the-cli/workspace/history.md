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
weight: 5307
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `history` command, it is possible to show the history of the current checked-out repository.

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

	Find more information at: https://www.permguard.com/docs/using-the-cli/how-to-use/

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

The `permguard history` command allows you to show the history of the current checked-out repository.

```bash
permguard history
```

output:

```bash
Your workspace history head/273165098782/9b3de5272b0447f2a8d1024937bdef11:

Commit c1d036a1afedb800b1dd0b89d1d4c3a4b070358765754f2ebc547ed0dcf0dc1b:
  - Tree: c7ed1a6a5be1b03460d47dfa6cee369384dbfc80644841da2ab9a74575ba12ff
  - Committer Timestamp: 2024-11-17 18:26:52 +0100 CET
  - Author Timestamp: 2024-11-17 18:26:52 +0100 CET

Commit 92dabde1bf3cae4472e72cfac8986c474bd3cbdb7468b36ab70f6b5cad9cb030:
  - Tree: 233ff1755c54987bd640f6b11748698e30d64b115a8c9ac1d74da9499c6fd94d
  - Committer Timestamp: 2024-11-17 18:07:07 +0100 CET
  - Author Timestamp: 2024-11-17 18:07:07 +0100 CET

Commit 941322d193e08109f9f8c1c7073698d5b6aa1c9a00b40e927f3c23a14ed6e614:
  - Tree: 28fb0c9ff09dbd908c58314daebb246a1634733f424234a4ef5f25c9f7e22780
  - Committer Timestamp: 2024-11-17 18:06:38 +0100 CET
  - Author Timestamp: 2024-11-17 18:06:38 +0100 CET
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard history --output json
```

output:

```bash
{
  "commits": [
    {
      "author": "unknown",
      "author_timestamp": "2024-11-17T18:26:52+01:00",
      "commit_id": "c1d036a1afedb800b1dd0b89d1d4c3a4b070358765754f2ebc547ed0dcf0dc1b",
      "committer": "unknown",
      "committer_timestamp": "2024-11-17T18:26:52+01:00",
      "parent": "92dabde1bf3cae4472e72cfac8986c474bd3cbdb7468b36ab70f6b5cad9cb030",
      "tree": "c7ed1a6a5be1b03460d47dfa6cee369384dbfc80644841da2ab9a74575ba12ff"
    },
    {
      "author": "unknown",
      "author_timestamp": "2024-11-17T18:07:07+01:00",
      "commit_id": "92dabde1bf3cae4472e72cfac8986c474bd3cbdb7468b36ab70f6b5cad9cb030",
      "committer": "unknown",
      "committer_timestamp": "2024-11-17T18:07:07+01:00",
      "parent": "941322d193e08109f9f8c1c7073698d5b6aa1c9a00b40e927f3c23a14ed6e614",
      "tree": "233ff1755c54987bd640f6b11748698e30d64b115a8c9ac1d74da9499c6fd94d"
    },
    {
      "author": "unknown",
      "author_timestamp": "2024-11-17T18:06:38+01:00",
      "commit_id": "941322d193e08109f9f8c1c7073698d5b6aa1c9a00b40e927f3c23a14ed6e614",
      "committer": "unknown",
      "committer_timestamp": "2024-11-17T18:06:38+01:00",
      "parent": "0000000000000000000000000000000000000000000000000000000000000000",
      "tree": "28fb0c9ff09dbd908c58314daebb246a1634733f424234a4ef5f25c9f7e22780"
    }
  ]
}
```

</details>
