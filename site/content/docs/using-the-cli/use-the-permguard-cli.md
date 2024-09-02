---
title: "Use the PermGuard CLI"
slug: "how-to-use"
description: ""
summary: ""
date: 2023-08-01T00:42:19+01:00
lastmod: 2023-08-01T00:42:19+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "use-the-permguard-cli-10802952ca15ef122a11e4287ee6f8ee"
weight: 5001
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

`PermGuard` offers a robust Command-line Interface (CLI) designed for the administration.
The CLI allows to Manage Accounts on the remote server, identities, tenants, repositories, schemas, domains, resources, and policies.

To view a list of commands available in the current PermGuard version, users can run the `permguard` command without any additional arguments.

```txt
  ____                      ____                     _
 |  _ \ ___ _ __ _ __ ___  / ___|_   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \| |  _| | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | |_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\____|\__,_|\__,_|_|  \__,_|

The official PermGuard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

PermGuard is an Open Source Multi-Account and Multi-Tenant Authorization Provider.

  Find more information at: https://www.permguard.com/docs/cli/how-to-use/

Usage:
  PermGuard Command Line Interface [flags]
  PermGuard [command]

Available Commands:
  accounts    Manage accounts on the remote server
  apply       Apply the plan to the remote repo
  authn       Manage tenants and identities on the remote server
  authz       Manage repositories on the remote server
  checkout    Checkout a repo
  clone       Clone an existing repo from a remote into the working directory
  completion  Generate the autocompletion script for the specified shell
  config      Configure the command line settings
  destroy     Destroy objects in the remote repo
  diff        Calculate the difference between the working directory and a remote repo
  help        Help about any command
  init        Initialize a new repository in the working directory
  plan        Plan the difference between the working directory and a remote repo to be applied
  pull        Feteches the latest changes from the server and build a remote state
  remote      Manage the set of remote servers you track
  repo        Manage the local repo
  validate    Validate source code in the working directory

Flags:
  -h, --help             help for PermGuard
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")

Use "PermGuard [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

To obtain detailed help for a specific command, users can utilize the --help option alongside the relevant subcommand.
For instance, to access help information about the `accounts` subcommand, users can execute the following command:

```bash
permguard --help
```

It's important to note that the output of the command line can be either in the default `TERMINAL` or `JSON` format by setting the output flag.

```bash
permguard accounts list
```

```bash
permguard accounts list --output json
```
