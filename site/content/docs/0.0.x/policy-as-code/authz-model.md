---
title: "AuthZ Manifest"
slug: "AuthZ Manifest"
description: ""
summary: ""
date: 2025-02-14T00:34:10+01:00
lastmod: 2025-02-14T00:34:10+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authz-manifest-2acc79fe1e014fe2ade6d301de843c14"
weight: 4002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The **AuthZ Manifest** is used to define the authorization model.

Below is an example of an `AuthZ Manifest`:

```json
{
    "metadata": {
        "name": "playground-cedar",
        "description": "A Permguard playground using the Cedar language.",
        "author": "Nitro Agility S.r.l.",
        "license": "Apache-2.0"
    },
    "runtimes": {
        "cedar0.0+": {
            "language": {
                "name": "cedar",
                "version": "0.0+"
            },
            "engine": {
                "name": "permguard",
                "version": "0.0+",
                "distribution": "community"
            }
        }
    },
    "partitions": {
        "root": {
            "location": {
                "path": "./",
                "mode": "file"
            },
            "runtime": "cedar0.0+",
            "schema": false
        }
    }
}
```

## **Metadata**

This section defines the metadata of the **authorization model**.

## **Runtime**

This section defines the available runtimes required by the **authorization model**.
Each of these runtimes is associated with a specific language and engine.

Both of them have a version, and the **+** means from that version to any other version. Without it, the version is fixed.

## **Partitions**

This section defines the partitions of the **authorization model** and mandates the presence of a ```root``` partition. Each partition is associated with a specific runtime and allows specifying if a schema is required.
Along with this, it is required to specify the location, which has a path and a mode (```file``` or ```directory```).
