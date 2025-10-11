---
title: "Install & Bootstrap"
slug: "Install & Bootstrap"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "install-and-bootstrap-25c10db057194ae3b83531088638a3fc"
weight: 1002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

To install locally and bootstrap **Permguard**, you need to run the AuthZ server and install the **Permguard CLI**.
This guide provides step-by-step instructions to help you get started.

For deployment, refer to the [DevOps](/docs/0.0.x/devops/authz-server/authz-server/) section.

## Start up the AuthZ Server

To startup the AuthZ server, you just need to run the Docker container.

```shell
docker pull permguard/all-in-one:latest
docker run --rm -it -p 9091:9091 -p 9092:9092 -p 9094:9094 permguard/all-in-one:latest
```

## Install the Command Line Interface

To install the Permguard CLI, the first step is to build it.

```shell
make build-cli
```

Then it is required to copy the binary to the desired location which has to be in the system path.

```shell
cp dist/permguard /usr/local/bin/permguard
```
