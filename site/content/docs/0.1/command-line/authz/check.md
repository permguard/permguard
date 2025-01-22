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
  "authorization_context": {
    "application_id": 268786704340,
    "policy_store": {
      "type": "ledger",
      "id": "fd1ac44e4afa4fc4beec622494d3175a"
    },
    "principal": {
      "type": "user",
      "id": "amy.smith@acmecorp.com",
      "source": "keycloak",
      "identity_token": "eyJhbGciOiJI...",
      "access_token": "eyJhbGciOiJI..."
    },
    "entities": {
      "schema": "cedar",
      "items": [
        {
          "uid": {
            "type": "Permguard::IAM::User",
            "id": "amy.smith@acmecorp.com"
          },
          "attrs": {
          },
          "parents": []
        },
        {
          "uid": {
            "type": "MagicFarmacia::Platform::Subscription",
            "id": "e3a786fd07e24bfa95ba4341d3695ae8"
          },
          "attrs": {
            "active": true
          },
          "parents": []
        }
      ]
    }
  },
  "subject": {
    "type": "user",
    "id": "amy.smith@acmecorp.com",
    "source": "keycloak",
    "properties": {}
  },
  "resource": {
    "type": "MagicFarmacia::Platform::Subscription",
    "id": "e3a786fd07e24bfa95ba4341d3695ae8",
    "properties": {}
  },
  "context": {
    "isSuperUser": true
  },
  "evaluations": [
    {
      "action": {
        "name": "MagicFarmacia::Platform::Action::view",
        "properties": {}
      }
    },
    {
      "action": {
        "name": "MagicFarmacia::Platform::Action::delete",
        "properties": {}
      }
    }
  ]
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
</details>

```bash
permguard authz check --appid 268786704340 /path/to/authorization_request.json -o json
```

output:

```json

```
