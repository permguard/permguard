---
title: "Run the AuthZ Server"
slug: "Run the AuthZ Server"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "run-authz-server-a6be8dbc1cc54c11ab5684f85461e9e4"
weight: 1003
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

To run the AuthZ server, you just need to run the Docker container.

```bash
docker pull permguard/all-in-one:latest
docker run --rm -it -p 9091:9091 -p 9092:9092 -p 9094:9094 permguard/all-in-one:latest
```
