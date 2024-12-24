---
title: "Use the Permguard CLI"
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
The **Permguard CLI** provides a robust toolset for interacting with Permguard servers.

The CLI is designed for two primary scenarios.

- In the context of **Permguard Server Administration**: it enables the management of `applications`, `identity sources`, `identities`, `tenants`, and `ledgers` directly on the remote server. This allows administrators to maintain and configure the system efficiently.
- For developers, the CLI supports a complete **Policy-as-Code Workspace**. It facilitates the local development of configuration artifacts such as `schemas`, `namespaces`, `resources`, `policies`, and `permissions`, integrating the essential toolchain required for the development lifecycle. These locally created artifacts can then be seamlessly applied to the remote server, ensuring a consistent and scalable approach to policy deployment across environments.

To view a list of commands available in the current Permguard version, users can run the **permguard** command without any additional arguments.

```txt
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

Permguard is an Open Source Multi-Application, Multi-Tenant, Zero-Trust Auth* Provider.

  Find more information at: https://www.permguard.com/docs/using-the-cli/how-to-use/

Usage:
  permguard [flags]
  permguard [command]

Available Commands:
  applications    Manage applications on the remote server
  apply       Apply the plan to the remote ledger
  authn       Manage tenants and identities on the remote server
  authz       Manage ledgers on the remote server
  checkout    Check out the contents of a remote ledger to the local permguard workspace
  clone       Clone a remote ledger to the local permguard workspace
  completion  Generate the autocompletion script for the specified shell
  config      Configure the command line settings
  help        Help about any command
  history     Show the history
  init        Initialize a permguard workspace
  objects     Manage the object store
  plan        Generate a plan of changes to apply to the remote ledger based on the differences between the local and remote states
  pull        Fetch the latest changes from the remote ledger and constructs the remote state.
  refresh     Scan source files in the current directory and synchronizes the local state
  remote      Manage remote server for tracking and interaction
  repo        Manage ledger settings and operations
  validate    Validate the local state for consistency and correctness

Flags:
  -h, --help             help for permguard
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")

Use "permguard [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

To obtain detailed help for a specific command, users can utilize the --help option alongside the relevant subcommand.
For instance, to access help information about the `applications` subcommand, users can execute the following command:

```bash
permguard applications --help
```

It's important to note that the output of the command line can be either in the default `TERMINAL` or `JSON` format by setting the output flag.

For instance to list all applications in the default terminal format, users can execute the following command:

```bash
permguard applications list
```

To list all applications in JSON format, users can execute the following command:

```bash
permguard applications list --output json
```
