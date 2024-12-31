---
title: "Check"
description: ""
summary: ""
date: 2024-12-30T11:00:00+01:00
lastmod: 2024-12-30T11:00:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "check-69711397-a43d-49f2-908d-575e47d68958"
weight: 5203
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
  permguard authz check --appid 268786704340 /path/to/authorization_request.json


  Find more information at: https://www.permguard.com/docs/0.1/using-the-cli/how-to-use/

Usage:
  permguard authz check [flags]

Flags:
      --appid int     application id
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
permguard authz check --appid 268786704340 /path/to/authorization_request.json
```

Below are other methods to pass the input:

```bash
permguard authz check --appid 268786704340 < /path/to/authorization_request.json
```

```bash
cat /path/to/authorization_request.json | permguard authz check --appid 268786704340
```

```bash
permguard authz check --appid 268786704340 <<EOF
{
  "principal": {
    "identity_token": "eyJhbGciOiJI...",
    "access_token": "eyJhbGciOiJI..."
  },
  "policy_store": {
    "type": "ledger",
    "id": "magicfarmacia",
    "version": "722164f552f2c8e582d4ef79270c7ec94b3633e8172af6ea53ffe1fdf64d66de"
  },
  "entities": {
    "schema": "cedar",
    "items": [
      {
        "uid": { "type": "Branch", "id": "96902499c04246f0bbe8f2e67a165a64" },
        "attrs": { "name": "Milan Office" },
        "parents": []
      }
    ]
  },
  "subject": {
    "type": "user",
    "id": "john.smith@acmecorp.com",
    "source": "keycloak",
    "properties": {}
  },
  "resource": {
    "type": "employee",
    "id": "8796159789",
    "properties": {
      "branch": {
        "id": "96902499c04246f0bbe8f2e67a165a64"
      }
    }
  },
  "action": {
    "name": "assignRole",
    "properties": {}
  },
  "context": {
    "time": "2024-12-26T23:02-45:00"
  }
}
EOF
```

output:

```bash
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard authz check --appid 268786704340 /path/to/authorization_request.json -o json
```

output:

```json

```
