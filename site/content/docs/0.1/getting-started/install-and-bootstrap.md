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
weight: 1003
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

To install locally and bootstrap **PermGuard**, you need to run the AuthZ server and install the PermGuard CLI.
This guide provides step-by-step instructions to help you get started.

For deployment, refer to the [DevOps](/docs/0.1/devops/authz-server/authorization-server) section.

## Install the AuthZ Server

To install the AuthZ server, you just need to run the Docker container.
Follow these steps:

```shell
docker run --rm -it -p 9091:9091  -p 9092:9092 -p 9094:9094 permguard/all-in-one:0.0.0.1
```

## Install the Command Line Interface (CLI)

To install the PermGuard CLI, the first step is to build it.

Run the following command:

```shell
make build-cli
```

Then it is required to copy the binary to the desired location which has to be in the system path.

```shell
cp bin/permguard-cli /usr/local/bin/permguard-cli
```
