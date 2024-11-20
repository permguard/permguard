---
title: "Objects"
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
Using the `objects` command, it is possible to manage the object store.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command manages the object store.

Examples:
  # list the objects in the workspace
  permguard objects

	Find more information at: https://www.permguard.com/docs/0.1/using-the-cli/how-to-use/

Usage:
  permguard objects [flags]
  permguard objects [command]

Available Commands:
  cat         Cat the object content

Flags:
      --all       all object types
      --blob      objects of the blob type
      --code      include objects from the code store
      --commit    objects of the commit type
  -h, --help      help for objects
      --objects   include objects from the object store
      --tree      objects of the tree type

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")

Use "permguard objects [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Get All Objects

The `permguard objects` command allows for the retrieval of all object store items.

```bash
permguard objects --all
```

output:

```bash
Your workspace objects:

	- 0a0b9ef638c0ea0e93cf92d6a257dbb4226e42c3eefaba86090870ab2505440a blob
	- 16ff0a36c04c4bd186f821033e3f2c91d192728b13e78d63d3f38f17fec422f2 blob
	- 233ff1755c54987bd640f6b11748698e30d64b115a8c9ac1d74da9499c6fd94d tree
	- 28fb0c9ff09dbd908c58314daebb246a1634733f424234a4ef5f25c9f7e22780 tree
	- 515e419b374c50ca44f0dd49cc83b7e52def3cc54ee6b6fb3a02d45007b13562 blob
	- 5d0e9cc5af16ae7e1cd2895bb411fe96b90a825538e64fc14ff889df05b62d59 blob
	- 92dabde1bf3cae4472e72cfac8986c474bd3cbdb7468b36ab70f6b5cad9cb030 commit
	- 941322d193e08109f9f8c1c7073698d5b6aa1c9a00b40e927f3c23a14ed6e614 commit
	- 95b32cd25a53e657667c38975c53e2d4a9ad7e8d6f130078cb1ec616b25e506d blob
	- c123402fcbf4520921df03b884325a2228c31abb5924e1b9f240ab866bf2ca11 blob
	- c1d036a1afedb800b1dd0b89d1d4c3a4b070358765754f2ebc547ed0dcf0dc1b commit
	- c7ed1a6a5be1b03460d47dfa6cee369384dbfc80644841da2ab9a74575ba12ff tree
	- eb28e2d5bae9092855b0497c0a39b564b27922d20c6f8f58dd44b4654d93a584 blob
	- ee1d3e9c9fb25ada345d8942c9f8ebe84de0139bfd53d61df0a4ce597b2dccc8 blob
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard objects --all --output json
```

output:

```bash
{
  "objects": [
    {
      "size": 1321,
      "type": "blob"
    },
    {
      "size": 164,
      "type": "blob"
    },
    {
      "size": 739,
      "type": "tree"
    },
    {
      "size": 739,
      "type": "tree"
    },
    {
      "size": 200,
      "type": "blob"
    },
    {
      "size": 157,
      "type": "blob"
    },
    {
      "size": 248,
      "type": "commit"
    },
    {
      "size": 248,
      "type": "commit"
    },
    {
      "size": 202,
      "type": "blob"
    },
    {
      "size": 178,
      "type": "blob"
    },
    {
      "size": 248,
      "type": "commit"
    },
    {
      "size": 233,
      "type": "tree"
    },
    {
      "size": 149,
      "type": "blob"
    },
    {
      "size": 182,
      "type": "blob"
    }
  ]
}
```

</details>
