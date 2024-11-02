---
title: "Coding"
slug: "Coding"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "coding-200a3b6d4f294f75969f5159b3147f63"
weight: 3013
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Permguard adopts a code-first approach to managing schemas, policies and permissions. This approach ensures that all configurations are defined in code, allowing them to be versioned, reviewed, and tested.

To enhance coding efficiency and comfort, Permguard provides several key commands:

- `refresh`: Generates the local state
- `validate`: Validates the configurations in the working directory
- `pull`: Fetches the remote changes and build a remote state
- `object`: Managed the object model.

## Refresh

The `refresh` command updates the local workspace by cleaning up temporary files, regenerating necessary configurations, and ensuring that the local source code is in sync with the expected state. This command focuses solely on the local workspace and the source code, without interacting with any remote repositories.

```bash
permguard refresh
```

## Validate

The `validate` command checks the configurations in the working directory for syntax errors and ensures that they are valid. This command is useful for identifying issues before applying changes to the server. This command focuses solely on the local workspace and the source code, without interacting with any remote repositories.

```bash
 permguard validate
```

## Pull

The `pull` command fetches the state from the remote Permguard server and stores it locally and finally build a remote state.

```bash
 permguard pull
```

## Objects

The `objects` command manages the object store, allowing users to display the contents of an object.
This command focuses solely on the local workspace and the source code, without interacting with any remote repositories.

```bash
 permguard objects
```
