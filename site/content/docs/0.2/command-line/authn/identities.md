---
title: "Identities"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "identities-85ba1774-52b6-4799-853f-326ff495e90c"
weight: 5103
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `identities` command, it is possible to manage identity.

```text
This command manages identities.

Usage:
  Permguard authn identities [flags]
  Permguard authn identities [command]

Available Commands:
  create      Create an identity
  delete      Delete an identity
  list        List identities
  update      Update an identity

Flags:
      --appid int   application id
  -h, --help          help for identities

Global Flags:
  -o, --output string   output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")
  -v, --verbose         true for verbose output

Use "Permguard authn identities [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Create an Identity

The `permguard authn identities create` command allows to create an identity for the mandatory input application and name.

```bash
permguard authn identities create --appid 268786704340 --kind user --name nicolagallo --identitysourceid 1da1d9094501425085859c60429163c2
```

output:

```bash
e151cba136214be98b2d1a02e797db60: nicolagallo
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard authn identities create --appid 268786704340 --kind user --name nicolagallo --identitysourceid 1da1d9094501425085859c60429163c2 --output json
```

output:

```bash
{
  "identities": [
    {
      "identity_id": "e151cba136214be98b2d1a02e797db60",
      "created_at": "2024-08-25T14:40:50.812Z",
      "updated_at": "2024-08-25T14:40:50.812Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "user",
      "name": "nicolagallo"
    }
  ]
}
```

</details>

## Get All Identity

The `permguard authn identities list` command allows for the retrieval of all identity.

```bash
permguard authn identities list --appid 268786704340 --identitysourceid 1da1d9094501425085859c60429163c2
```

output:

```bash
028f40d8ee034c6ea1e6ef853db7b7f5: giuliarossi
4697f870532046d7b0e6a33efdcffc17: system-administrator
4c637a422bb3477dad41fdbc44c71ed0: ashleyjohnson
804ecc6b562242069c7837f63fd1a3b3: branch-manager
913d1cfc74a249ec9e11a0b89d791010: lucabianchi
94bebf6b598d48caad8ca90aee9e796e: johndoe
b0b3dd968a5a4cb19e3871921b1e3519: jamessmith
e151cba136214be98b2d1a02e797db60: nicolagallo
ea80f2bdd56c4037837e31bd9243db88: emilybrown
fdbc2ddfa4c5401eac19bd655efefe5c: marcobianchi
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard authn identities list --appid 268786704340 --identitysourceid --output json
```

output:

```bash
{
  "identities": [
    {
      "identity_id": "028f40d8ee034c6ea1e6ef853db7b7f5",
      "created_at": "2024-08-25T14:44:41.966Z",
      "updated_at": "2024-08-25T14:44:41.966Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "user",
      "name": "giuliarossi"
    },
    {
      "identity_id": "4697f870532046d7b0e6a33efdcffc17",
      "created_at": "2024-08-25T14:45:27.123Z",
      "updated_at": "2024-08-25T14:45:27.123Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "actor",
      "name": "system-administrator"
    },
    {
      "identity_id": "4c637a422bb3477dad41fdbc44c71ed0",
      "created_at": "2024-08-25T14:44:47.597Z",
      "updated_at": "2024-08-25T14:44:47.597Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "user",
      "name": "ashleyjohnson"
    },
    {
      "identity_id": "804ecc6b562242069c7837f63fd1a3b3",
      "created_at": "2024-08-25T14:45:28.167Z",
      "updated_at": "2024-08-25T14:45:28.167Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "actor",
      "name": "branch-manager"
    },
    {
      "identity_id": "913d1cfc74a249ec9e11a0b89d791010",
      "created_at": "2024-08-25T14:44:43.133Z",
      "updated_at": "2024-08-25T14:44:43.133Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "user",
      "name": "lucabianchi"
    },
    {
      "identity_id": "94bebf6b598d48caad8ca90aee9e796e",
      "created_at": "2024-08-25T14:44:46.427Z",
      "updated_at": "2024-08-25T14:44:46.427Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "user",
      "name": "johndoe"
    },
    {
      "identity_id": "b0b3dd968a5a4cb19e3871921b1e3519",
      "created_at": "2024-08-25T14:44:44.176Z",
      "updated_at": "2024-08-25T14:44:44.176Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "user",
      "name": "jamessmith"
    },
    {
      "identity_id": "e151cba136214be98b2d1a02e797db60",
      "created_at": "2024-08-25T14:40:50.812Z",
      "updated_at": "2024-08-25T14:40:50.812Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "user",
      "name": "nicolagallo"
    },
    {
      "identity_id": "ea80f2bdd56c4037837e31bd9243db88",
      "created_at": "2024-08-25T14:44:45.312Z",
      "updated_at": "2024-08-25T14:44:45.312Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "user",
      "name": "emilybrown"
    },
    {
      "identity_id": "fdbc2ddfa4c5401eac19bd655efefe5c",
      "created_at": "2024-08-25T14:44:40.925Z",
      "updated_at": "2024-08-25T14:44:40.925Z",
      "application_id": 268786704340,
      "identity_source_id": "1da1d9094501425085859c60429163c2",
      "identity_type": "user",
      "name": "marcobianchi"
    }
  ]
}
```

</details>
