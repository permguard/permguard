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
weight: 6001
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

`PermGuard` offers a robust Command-line Interface (CLI) designed for the administration.
The CLI allows to manage accounts, identities, tenants, repositories, schemas, domains, resources, and policies.

To view a list of commands available in the current PermGuard version, users can run the `permguard` command without any additional arguments.

```txt
The Official PermGuard CLI
Copyright (c) 2022 Nitro Agility S.r.l.

  Find more information at: https://www.permguard.com/docs/cli/how-to-use/

Usage:
  PermGuard CLI [flags]
  PermGuard [command]

Available Commands:
  accounts    Manage Accounts
  authn       Manage Tenants, Identity Sources and Identities
  authz       Manage Repositories and Trusted Delegations
  completion  Generate the autocompletion script for the specified shell
  config      Configure CLI settings
  help        Help about any command

Flags:
  -h, --help            help for PermGuard
  -o, --output string   output format (default "terminal")
  -v, --verbose         true for verbose output

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
