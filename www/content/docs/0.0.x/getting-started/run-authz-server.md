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

The AuthZ Server can be deployed as a self-contained Docker container, providing an isolated and reproducible runtime environment.

To start the server using the latest container image:

```bash
docker pull permguard/all-in-one:latest
docker run --rm -it \
  -p 9091:9091 \
  -p 9092:9092 \
  -p 9094:9094 \
  permguard/all-in-one:latest
```

Configuration parameters can be injected via environment variables, allowing full control over runtime behavior without modifying the container image.

The complete list of configurable parameters is documented in the [CLI Configuration Options](/docs/0.0.x/devops/authz-server/configuration-options/).

Example with debugging enabled:

```bash
docker pull permguard/all-in-one:latest
docker run --rm -it \
  -p 9091:9091 \
  -p 9092:9092 \
  -p 9094:9094 \
  -e PERMGUARD_DEBUG="TRUE" \
  permguard/all-in-one:latest
```

When `PERMGUARD_DEBUG` is set to `TRUE`, the AuthZ server operates in debug mode, providing verbose logging and diagnostic output suitable for development and troubleshooting scenarios.

It is also possible to access the local SQLite database used by the AuthZ Server by mounting a host directory into the container.

This allows direct inspection or interaction with the database files from the host system.

```bash
docker pull permguard/all-in-one:latest
docker run --rm -it \
  -v ./local:/opt/permguard/volume
  -p 9091:9091 \
  -p 9092:9092 \
  -p 9094:9094 \
  -e PERMGUARD_DEBUG="TRUE" \
  permguard/all-in-one:latest
```

In this setup, the `SQLite` database will be accessible on the host under the mounted path `./local`.
