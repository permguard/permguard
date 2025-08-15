---
title: "Validate"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "validate-87643cd6-ef51-4711-840d-fac78b9210c5"
weight: 6310
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `validate` command, it is possible to validate the local state for consistency and correctness.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command validates the local state for consistency and correctness.

Examples:
  # validate the local state for consistency and correctness",
  permguard validate

  Find more information at: https://community.permguard.com/docs/0.0.x/command-line/how-to-use/

Usage:
  permguard validate [flags]

Flags:
  -h, --help   help for validate

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Validate the local state

The `permguard validate` command allows you to validate the local state for consistency and correctness.

```bash
permguard validate
```

output:

```bash
Your workspace has on error in the following file:

  - 'platform/platform-policies.cedar'
    1: parser error: parse error at <input>:15:5 "n": exact got whe want ;

Please fix the errors to proceed.
Failed to validate the current workspace.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard validate --output json
```

output:

```json
{
  "error": "cli: operation on file failed",
  "validation_errors": {
    "platform/platform-policies.cedar": {
      "1": {
        "path": "platform/platform-policies.cedar",
        "section": "parser error: parse error at <input>:15:5 \"n\": exact got whe want ;"
      }
    }
  }
}
```

</details>
