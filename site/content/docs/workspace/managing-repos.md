---
title: "Managing Repos"
slug: "Managing Repos"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "managing-repos-877e4c04952b438fb838d3ceff1aedff"
weight: 3012
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

PermGuard supports multiple repos for each remote, providing flexible management for both coding and provisioning tasks. When making changes, it is crucial to specify the remote where these changes will be pushed.

To ensure that changes are provisioned correctly, you must first check out the appropriate repository. This repository will then serve as the target for provisioning and deploying the updates.

You can check out a repository using the `checkout` command:

```bash
 permguard checkout dev/268786704340/magicfarmacia-v0.0
```

In this command, the first parameter is the remote, followed by the account ID, and finally the repository identifier. The format used is `<remote>/<account-id>/<repository-name>`.
