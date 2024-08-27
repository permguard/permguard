---
title: "Managing Remotes"
slug: "Managing Remotes"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "managing-remotes-b663ce40aa4e4d85bf70d3617535bce0"
weight: 3010
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

PermGuard can be installed in any environment, with the capability to deploy multiple instances of the PermGuard server.

A common practice is to deploy a dedicated PermGuard server for each environment, such as development, staging, and production.

When executing provisioning and pull operations, it is essential to specify the correct remote server in the command.

A remote can be added using the remote command:

```bash
❯ permguard remote add dev 268786704340/magicfarmacia-v0.0
```

In this command, the first parameter is the name of the remote, and the second parameter is the repository identifier, which follows the notation `<account-id>/<repository-name>`. If no remote name is specified, it defaults to origin.

If the PermGuard endpoints differ from those configured globally in the CLI, they can be explicitly defined:

```bash
❯ permguard remote add dev 268786704340/magicfarmacia-v0.0 --aap-target localhost:9091 --pap-target localhost:9092
```

To avoid specifying the remote server each time, it is possible to set the default remote server, which is associated with origin by default:

```bash
❯ permguard remote set-default dev
```
