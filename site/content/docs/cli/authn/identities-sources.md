---
title: "Identity Sources Management"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "identities-sources-c8cedcba-38bd-4afb-9fbb-e3ce1d23c8bb"
weight: 6102
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `IdentitySources` commands, it is possible to manage identity sources.

```text
This command manages identity sources.

Usage:
  PermGuard authn identitysources [flags]
  PermGuard authn identitysources [command]

Available Commands:
  create      Create an identity source
  delete      Delete an identity source
  list        List identity sources
  update      Update an identity source

Flags:
      --account int   account id filter
  -h, --help          help for identitysources

Global Flags:
  -o, --output string   output format (default "terminal")
  -v, --verbose         true for verbose output

Use "PermGuard authn identitysources [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

## Create an IdentitySource

The `permguard authn identitysources create` command allows to create an identity source for the mandatory input account and name.

{{< tabs "permguard-identitysources-create" >}}
{{< tab "terminal" >}}

```bash
permguard authn identitysources create --account 268786704340 --name google
```

output:

```bash
1da1d9094501425085859c60429163c2: google
```

{{< /tab >}}
{{< tab "json" >}}

```bash
permguard authn identitysources create --account 268786704340 --name google --output json
```

output:

```bash
{
  "identity_sources": [
    {
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "created_at": "2024-08-25T14:36:08.677Z",
      "updated_at": "2024-08-25T14:36:08.677Z",
      "account_id": 268786704340,
      "name": "google"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}

## Get All IdentitySource

The `permguard authn identitysources list` command allows for the retrieval of all identity sources.

{{< tabs "permguard-identitysources-list" >}}
{{< tab "terminal" >}}

```bash
permguard authn identitysources list --account 268786704340
```

output:

```bash
1da1d9094501425085859c60429163c2: google
82b293c0c4eb4f65a8d6f29adfeb8ca5: facebook
````

{{< /tab >}}
{{< tab "json" >}}

```bash
permguard authn identitysources list --account 268786704340 --output json
```

output:

```bash
{
  "identity_sources": [
    {
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "created_at": "2024-08-25T14:36:08.677Z",
      "updated_at": "2024-08-25T14:36:08.677Z",
      "account_id": 268786704340,
      "name": "google"
    },
    {
      "identity_source_id": "82b293c0c4eb4f65a8d6f29adfeb8ca5",
      "created_at": "2024-08-25T14:36:23.169Z",
      "updated_at": "2024-08-25T14:36:23.169Z",
      "account_id": 268786704340,
      "name": "facebook"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}
