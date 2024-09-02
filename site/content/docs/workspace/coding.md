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

PermGuard adopts a code-first approach to managing schemas, policies and permissions. This approach ensures that all configurations are defined in code, allowing them to be versioned, reviewed, and tested.

To enhance coding efficiency and comfort, PermGuard provides several key commands:

- `validate`: Validates the configurations in the working directory
- `pull`: Fetches the remote changes and build a remote state
- `diff`: Calculate and output the differences between the working directory and the remote server

## Validate

The `validate` command checks the configurations in the working directory for syntax errors and ensures that they are valid. This command is useful for identifying issues before applying changes to the server.

```bash
❯ permguard validate
```

## Pull

The `pull` command fetches the state from the remote PermGuard server and stores it locally and finally build a remote state.

```bash
❯ permguard pull
```

## Diff

The `diff` command first performs a `fetch` to retrieve the latest state from the remote server, and then calculates the differences between the working directory and the remote server.

```bash
❯ permguard diff
```
