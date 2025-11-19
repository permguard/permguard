---
title: "AuthZServer"
slug: "AuthZServer"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authorization-server-51e885211e99e6d718992b041375f958"
weight: 7101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** is composed of several internal components that together form the **AuthZServer**.

The `AuthZServer` can run in an `all-in-one` configuration, where all components operate within a single instance, or it can be deployed in a distributed setup where each instance takes on a specific role such as `control-plane`, `data-plane`, or both.

{{< callout context="note" icon="info-circle" >}}
Services can be configured using either environment variables or [configuration options](/docs/0.0.x/devops/authz-server/configuration-options/). Each CLI option has a corresponding environment variable named `PERMGUARD_<OPTION_NAME>`. For example, the `--debug` option maps to the `PERMGUARD_DEBUG` environment variable.
{{< /callout >}}
