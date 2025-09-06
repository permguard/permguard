---
title: "Resource Pathing"
slug: "Resource Pathing"
description: ""
summary: ""
date: 2023-08-01T00:25:01+01:00
lastmod: 2023-08-01T00:25:01+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "resource-pathing-aac9fddccc2c417cbc1393e16518d34b"
weight: 2305
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

In **Permguard**, an **AuthZ Server** is a logical server composed of multiple nodes. It includes the following components:

- **Zone Administration Point (ZAP)**
- **Policy Administration Point (PAP)**
- **Policy Information Point (PIP)**
- **Policy Decision Point (PDP)**

This **AuthZ Server** manages various elements such as **ledgers**.
Due to the complexity of these resources, a **structured pathing mechanism** is essential for efficient management and access control.

{{< callout context="note" icon="info-circle" >}}
An environment can have multiple **AuthZ Servers**, so it is important to reference each one explicitly.
There is no guarantee that the same resource will be unique across all servers.
{{< /callout >}}

To reference a specific **zone** in an **AuthZ Server**, use the following **URI format**:

```text
 protocol    host       zone
┌───┴────┐┌───┴───┐ ┌────┴─────┐
permguard@localhost/273165098782
```

## Ledger Pathing

To reference a specific ledger in an **AuthZ Server**, use the following URI format:

```text
 protocol    host       zone                 ledger
┌───┴────┐┌───┴───┐ ┌────┴─────┐         ┌─────┴─────┐
permguard@localhost/273165098782/ledgers/magicfarmacia
```

A policy can be referenced using the following URI format:

```text
 protocol    host       zone                 ledger                                 version                           partition    policy
┌───┴────┐┌───┴───┐ ┌────┴─────┐         ┌─────┴─────┐ ┌───────────────────────────────┴──────────────────────────────┐ ┌─┴─┐┌───────┴────────┐
permguard@localhost/273165098782/ledgers/magicfarmacia/722164f552f2c8e582d4ef79270c7ec94b3633e8172af6ea53ffe1fdf64d66de/root/assign-role-branch
```
