---
title: "Config"
description: ""
summary: ""
date: 2023-08-10T20:39:08+01:00
lastmod: 2023-08-10T20:39:08+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "config-cc889e190a223318e9616ef4e73dea17"
weight: 6002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `config` command, it is possible to manage the CLI configurations.

The configuration file is stored in `~/.permguard/config.toml`.

```text
  ____                                               _
 |  _ \ ___ _ __ _ __ ___   __ _ _   _  __ _ _ __ __| |
 | |_) / _ \ '__| '_ ` _ \ / _` | | | |/ _` | '__/ _` |
 |  __/  __/ |  | | | | | | (_| | |_| | (_| | | | (_| |
 |_|   \___|_|  |_| |_| |_|\__, |\__,_|\__,_|_|  \__,_|
                           |___/

The official Permguard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.

This command configures the command line settings.

  Find more information at: https://www.permguard.com/docs/0.1/command-line/how-to-use/

Usage:
  permguard config [flags]
  permguard config [command]

Available Commands:
  pap-get-target Get the pap grpc target
  pap-set-target Set the pap grpc target
  pdp-get-target Get the pdp grpc target
  pdp-set-target Set the pdp grpc target
  reset          Reset the cli config settings
  zap-get-target Get the zap grpc target
  zap-set-target Set the zap grpc target

Flags:
  -h, --help   help for config

Global Flags:
  -o, --output string    output format (default "terminal")
  -v, --verbose          true for verbose output
  -w, --workdir string   workdir (default ".")

Use "permguard config [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of Permguard may differ from the example provided on this page.
{{< /callout >}}

## Reset the Config

The `permguard config reset` command allows to reset the CLI configurations.

```bash
permguard config reset
```

output:

```bash
 The cli config file ~/.permguard/config.toml has been reset.
```

<details>
  <summary>
    JSON Output
  </summary>

```bash
permguard config reset --output json
```

output:

```json
{
  "cli": {
    "config_file": "~/.permguard/config.toml"
  }
}
```

</details>

## Tragets

Targets can be set using the following commands

```bash
permguard config  zap-get-target localhost:9091
```

```bash
permguard config  pap-get-target localhost:9092
```

```bash
permguard config  pip-get-target localhost:9093
```

```bash
permguard config  pdp-get-target localhost:9094
```

The targets can be retrieved using the following commands

```bash
permguard config  zap-get-target
```

```bash
permguard config  pap-get-target
```

```bash
permguard config  pip-get-target
```

```bash
permguard config  pdp-get-target
```
