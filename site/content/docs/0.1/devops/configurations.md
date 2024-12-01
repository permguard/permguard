---
title: "Configurations"
slug: "Configurations"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "configurations-51e885211e99e6d718992b041375f958"
weight: 6001
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** consists of several services, which can be deployed either on a single instance using the `all-in-one` distribution, or individually using separate distributions for each service."

As a best practice, deploying the services in a single instance for production environments is not recommended. It is preferable to deploy the services separately in a distributed manner. This approach enables independent scaling of each service, enhancing flexibility and performance.

{{< callout context="note" icon="info-circle" >}}
Services can be configured either using Environment Variables or via [CLI flags](/docs/0.1/devops/cli-flags/). Each CLI flag corresponds to an equivalent Environment Variable named `PERMGUARD_<FLAG_NAME>`. For example, the `--debug` flag has an equivalent environment variable `PERMGUARD_DEBUG`.
{{< /callout >}}
