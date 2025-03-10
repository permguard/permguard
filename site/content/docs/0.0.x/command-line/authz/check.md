---
title: "Check"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "check-69711397-a43d-49f2-908d-575e47d68958"
weight: 6203
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Using the `check` command, it is possible to check authz requests.

```text
This command checks an authorization request.

Examples:
  # check an authorization request
  permguard authz check --zoneid 273165098782 /path/to/authorization_request.json


  Find more information at: https://www.permguard.com/docs/0.0.x/command-line/how-to-use/

Usage:
  permguard authz check [flags]

Flags:
      --zoneid int    zone id
  -h, --help          help for check

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Check an Authorization Request

The `permguard authz check` command allows to check an authorization request.

```bash
permguard authz check --zoneid 273165098782 /path/to/authorization_request.json
```

Below are other methods to pass the input:

```bash
permguard authz check --zoneid 273165098782 < /path/to/authorization_request.json
```

```bash
cat /path/to/authorization_request.json | permguard authz check --zoneid 273165098782
```

output:

```bash
Authorization check response: true
```

<details>
  <summary>
    JSON Output
  </summary>

  ```bash
  permguard authz check --zoneid 273165098782 /path/to/authorization_request.json -o json
  ```

  output:

  ```json
  {
    "authorization_check": {
      "decision": true,
      "context": {},
      "evaluations": [
        {
          "decision": true,
          "context": {}
        }
      ]
    }
  }
  ```

</details>
