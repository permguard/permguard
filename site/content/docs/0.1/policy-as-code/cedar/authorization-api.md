---
title: "AuthZ Model"
slug: "AuthZ Model"
description: ""
summary: ""
date: 2025-02-14T00:34:10+01:00
lastmod: 2025-02-14T00:34:10+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authz-model-f4b0330df22d49649f63eb411f00e47b"
weight: 4103
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
The **authorization model** defines the data structure and inputs of the AuthZ model, used in both the Authorization API and Policy as Code.

## Authorization API

The request payload must comply with the `Cedar` language, meaning the input should be in a format that `Cedar` can process.
