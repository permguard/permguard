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
❯ permguard authn identitysources create --account 789251338948 --name permguard
8bd19f65-c92d-4fc4-97d7-c5e553e9d5c4: permguard
```

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authn identitysources create --account 789251338948 --name permguard --output json
{
  "identity_sources": [
    {
      "identity_source_id": "8bd19f65-c92d-4fc4-97d7-c5e553e9d5c4",
      "created_at": "2023-04-01T09:48:06.537384Z",
      "updated_at": "2023-04-01T09:48:06.537384Z",
      "account_id": 890669113560,
      "name": "permguard"
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
❯ permguard authn identitysources list --account 789251338948
56ed842a-e216-4726-9a80-2794c92a5a98: default
8bd19f65-c92d-4fc4-97d7-c5e553e9d5c4: permguard
```

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authn identitysources list --account 789251338948 --output json
{
  "identity_sources": [
    {
      "identity_source_id": "56ed842a-e216-4726-9a80-2794c92a5a98",
      "created_at": "2023-04-01T09:42:40.231028Z",
      "updated_at": "2023-04-01T09:42:40.231028Z",
      "account_id": 890669113560,
      "name": "default"
    },
    {
      "identity_source_id": "8bd19f65-c92d-4fc4-97d7-c5e553e9d5c4",
      "created_at": "2023-04-01T09:48:06.537384Z",
      "updated_at": "2023-04-01T09:48:06.537384Z",
      "account_id": 890669113560,
      "name": "permguard"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}
