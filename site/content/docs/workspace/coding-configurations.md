---
title: "Coding Configurations"
slug: "Coding Configurations"
description: ""
summary: ""
date: 2023-08-01T00:56:12+01:00
lastmod: 2023-08-01T00:56:12+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "coding-configurations-eafd5d5a5b66442799398819043d8e48"
weight: 3012
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
- `fetch`: Fetches the remote state from the remote server
- `diff`: Calculate and output the differences between the working directory and the remote server
- `merge`: Merges the remote configurations into the working directory.

## Validate

The `validate` command checks the configurations in the working directory for syntax errors and ensures that they are valid. This command is useful for identifying issues before applying changes to the server.

```bash
❯ permguard validate
```

## Fetch

The `fetch` command retrieves the state from the remote PermGuard server and stores it locally. This is necessary to perform merges and provisioning operations.

```bash
❯ permguard fetch
```

## Diff

The `diff` command first performs a `fetch` to retrieve the latest state from the remote server, and then calculates the differences between the working directory and the remote server.

```bash
❯ permguard diff
```

## Merge

The `merge` command fetches the configurations from the remote server and merges them into the working directory. This command is useful for synchronizing the configurations between the local and remote environments.

```bash
❯ permguard merge
```
