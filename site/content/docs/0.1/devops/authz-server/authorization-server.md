---
title: "Authorization Server"
slug: "Authorization Server"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authorization-server-51e885211e99e6d718992b041375f958"
weight: 6101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**PermGuard** is composed of multiple services that together form the **Authorization Server**. These services can be deployed either as a single instance using the `all-in-one` distribution or separately, with each service running in its own instance.

{{< callout context="note" icon="info-circle" >}}
Services can be configured using either environment variables or [CLI options](/docs/0.1/devops/authz-server/configuration-options/). Each CLI option has a corresponding environment variable named `PERMGUARD_<OPTION_NAME>`. For example, the `--debug` option maps to the `PERMGUARD_DEBUG` environment variable.
{{< /callout >}}
