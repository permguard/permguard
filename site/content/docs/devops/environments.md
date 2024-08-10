---
title: "Environments"
slug: "Environments"
description: ""
summary: ""
date: 2023-08-08T12:46:04+01:00
lastmod: 2023-08-08T12:46:04+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "environments-ee65b24822a6419f8357b1f9f7e1c1b6"
weight: 7002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
`PermGuard` takes a firm stance on environments, discouraging the creation of multiple environments within a single account. Instead, each account must be labeled by the owner with a specific environment. This approach is enforced to minimize the security risks associated with the software.

{{< callout context="danger" icon="alert-octagon" >}}
Creating a schema within a single account to represent multiple environments of the same schema is strongly discouraged as it is considered a bad practice
{{< /callout >}}
