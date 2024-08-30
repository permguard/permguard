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
weight: 3011
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

PermGuard can be installed in any environment, offering the flexibility to deploy multiple instances of the PermGuard server.

A recommended approach is to deploy a dedicated PermGuard server for each environment, such as development, staging, and production. This separation ensures isolated and secure management of permissions tailored to each stage of your deployment pipeline.

When managing one or more servers, and provisioning to any of them, it is essential to properly configure the available remote connections. This configuration enables seamless communication and coordination between the various PermGuard instances.

A remote can be added using the remote command:

```bash
❯ permguard remote add dev server.permguard.com
```

and it can be removed using the remote command:

```bash
❯ permguard remote remove dev
```

If the PermGuard server ports differ from the default values (`aap`:`9091` and `pap`:`9092`), you can specify the custom port numbers using the `--aap` and `--pap` flag:

```bash
❯ permguard remote add dev server.permguard.com --aap 9095 --pap 9096
```
