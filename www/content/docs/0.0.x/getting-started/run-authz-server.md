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

The **AuthZ Server** acts as the **control plane** for Permguard: it manages policies, trust configuration, and governance rules.

By default, the server also includes an embedded **data plane**, allowing it to evaluate and enforce authorization decisions on its own.
This makes the container self-contained and ideal for development, testing, or simple deployments.

In production environments, however, enforcement should be **distributed**.
Dedicated data plane instances can be deployed close to workloads—inside applications, sidecar proxies, gateways, or edge nodes—so authorization decisions are enforced at the appropriate boundary with low latency and high resilience.

To start the server using the latest container image:

```bash
docker pull permguard/all-in-one:latest
docker run --rm -it \
  -p 9091:9091 \
  -p 9092:9092 \
  -p 9094:9094 \
  permguard/all-in-one:latest
```

When running Permguard from its Docker image, configuration parameters are supplied through environment variables, allowing runtime behavior to be customized without modifying the image itself.

The full list of available configuration parameters is documented in the [Authz Server Configuration Options](/docs/0.0.x/devops/authz-server/configuration-options/).

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

It is also possible to access the local SQLite database used by the `AuthZ Server` by mounting a host directory into the container.

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
