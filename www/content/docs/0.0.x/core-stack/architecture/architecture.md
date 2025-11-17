---
title: "Architecture"
slug: "Architecture"
description: ""
summary: ""
date: 2023-08-15T14:31:58+01:00
lastmod: 2023-08-15T14:31:58+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "architecture-3d21ce1c1c77ac6959efbd27f652a69e"
weight: 10101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

## Control-Plane and Data-Plane

**Permguard** is deployed as an `AuthZServer`, which is composed of several internal components.
These components are grouped into two main roles: the `control-plane` and the `data-plane`.

The server can run all components together in a single instance using the `all-in-one` distribution, or each component can be deployed separately using dedicated distributions.

---

<div style="text-align: center">
  <img alt="Permguard Components" src="/images/diagrams/permguard-components.png"/>
</div>

---

The `control-plane` is composed of:

- **Zone Administration Point (ZAP)**
- **Policy Administration Point (PAP)**
- **Policy Information Point (PIP)**

The `data-plane` consists of:

- **Policy Decision Point (PDP)**

## Zone Administration Point (ZAP)

The `Zone Administration Point (ZAP)` serves as the central repository for managing zone information and configurations.
It also exposes an administration API.

## Policy Administration Point (PAP)

The `Policy Administration Point (PAP)` is responsible for storing and managing zone policies.
It provides an administration API for creating, updating, and validating policies.

## Policy Information Point (PIP)

The `Policy Information Point (PIP)` supplies additional information required by the `Policy Decision Point (PDP)` to compute decisions.
It acts as an information provider in the authorization pipeline.

## Policy Decision Point (PDP)

The `Policy Decision Point (PDP)` evaluates policies and produces authorization decisions.
It can operate in two modes:

- **Remote data-plane**:
  Provides fully consistent decisions, but performance and availability depend on network connectivity.
  Network congestion, latency, or partitions can slow down responses or make the PDP temporarily unreachable.

- **Proximity data-plane**:
  Deployed close to the caller and operates under an eventually consistent model.
  It provides low-latency, resilient decisions by evaluating policies locally and synchronizing updates asynchronously.
  During network partitions, a proximity PDP may temporarily operate with slightly outdated policies until synchronization resumes.
