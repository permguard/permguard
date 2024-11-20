---
title: "Refresh"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "refresh-5602911d-77a0-434a-93b5-2c36bd9877c2"
weight: 5309
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `refresh` command, it is possible to scan source files in the current workspace and synchronize the local state.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command scans source files in the current workspace and synchronizes the local state.

Examples:
  # scan source files in the current directory and synchronizes the local state
  permguard refresh

	Find more information at: https://www.permguard.com/docs/0.1/using-the-cli/how-to-use/

Usage:
  permguard refresh [flags]

Flags:
  -h, --help   help for refresh

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Refresh the workspace state

The `permguard refresh` command allows you to scan source files in the current workspace and synchronize the local state.

```bash
permguard refresh
```

output:

```bash
Your workspace has errors.
Please validate and fix the errors to proceed.
Failed to refresh the current workspace.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard refresh --output json
```

output:

```bash
{
  "error_code": "08102",
  "error_message": "cli: operation on file failed",
  "validation_errors": {
    "codegen-96452-2dee167e..yml": {
      "1": {
        "path": "codegen-96452-2dee167e..yml",
        "section": "permcode: invalid name 'pharmacy-branch-mana@gement'"
      }
    }
  }
}
```

</details>
