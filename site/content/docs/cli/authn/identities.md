---
title: "Identities Management"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "identities-85ba1774-52b6-4799-853f-326ff495e90c"
weight: 6103
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `Identities` commands, it is possible to manage identity.

```text
This command manages identities.

Usage:
  PermGuard authn identities [flags]
  PermGuard authn identities [command]

Available Commands:
  create      Create an identity
  delete      Delete an identity
  list        List identities
  update      Update an identity

Flags:
      --account int   account id filter
  -h, --help          help for identities

Global Flags:
  -o, --output string   output format (default "terminal")
  -v, --verbose         true for verbose output

Use "PermGuard authn identities [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

## Create an Identity

The `permguard authn identities create` command allows to create an identity for the mandatory input account and name.

{{< tabs "permguard-identities-create" >}}
{{< tab "terminal" >}}

```bash
❯ permguard authn identities create --account 837151783797 --kind user --name nicolagallo --identitysourceid 6d492d4a-8752-405f-a8b3-859b5a219e56
7e43160f-d4a3-4301-9139-6e2b78b9290b: nicolagallo
```

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authn identities create --account 837151783797 --kind user --name nicolagallo --identitysourceid 6d492d4a-8752-405f-a8b3-859b5a219e56 --output json
{
  "identity": [
    {
      "identity_id": "7e43160f-d4a3-4301-9139-6e2b78b9290b",
      "created_at": "2023-04-01T16:36:08.568115Z",
      "updated_at": "2023-04-01T16:36:08.568115Z",
      "account_id": 837151783797,
      "identity_source_id": "6d492d4a-8752-405f-a8b3-859b5a219e56",
      "identity_type": "user",
      "name": "nicolagallo"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}

## Get All Identity

The `permguard authn identities list` command allows for the retrieval of all identity.

{{< tabs "permguard-identities-list" >}}
{{< tab "terminal" >}}

```bash
❯ permguard authn identities list --account 837151783797 --identitysourceid 6d492d4a-8752-405f-a8b3-859b5a219e56
7e43160f-d4a3-4301-9139-6e2b78b9290b: nicolagallo
ad5ef94c-f996-4242-af90-eda96abb8206: manager
```

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authn identities list --account 837151783797 --identitysourceid 6d492d4a-8752-405f-a8b3-859b5a219e56 --output json
{
  "identity": [
    {
      "identity_id": "7e43160f-d4a3-4301-9139-6e2b78b9290b",
      "created_at": "2023-04-01T16:36:08.568115Z",
      "updated_at": "2023-04-01T16:36:08.568115Z",
      "account_id": 837151783797,
      "identity_source_id": "6d492d4a-8752-405f-a8b3-859b5a219e56",
      "identity_type": "user",
      "name": "nicolagallo"
    },
    {
      "identity_id": "ad5ef94c-f996-4242-af90-eda96abb8206",
      "created_at": "2023-04-01T16:37:16.446177Z",
      "updated_at": "2023-04-01T16:37:16.446177Z",
      "account_id": 837151783797,
      "identity_source_id": "6d492d4a-8752-405f-a8b3-859b5a219e56",
      "identity_type": "role",
      "name": "manager"
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}
